#define MS_CLASS "RTC::RtpStreamSend"
// #define MS_LOG_DEV

#include "RTC/RtpStreamSend.hpp"
#include "DepLibUV.hpp"
#include "Logger.hpp"
#include "Utils.hpp"
#include "RTC/SeqManager.hpp"

namespace RTC
{
	/* Static. */

	// 17: 16 bit mask + the initial sequence number.
	static constexpr size_t MaxRequestedPackets{ 17 };
	static std::vector<uint16_t> RetransmissionContainer(MaxRequestedPackets + 1); // sequence ids of packets
	// Don't retransmit packets older than this (ms).
	static constexpr uint32_t MaxRetransmissionDelay{ 2000 };
	static constexpr uint32_t DefaultRtt{ 100 };

  /* RtpStreamSend::Buffer methods */

  // Access the first item in array
	const RtpStreamSend::BufferItem& RtpStreamSend::Buffer::first() const
	{ 
		MS_ASSERT(vctr.size() > 0 && maxsize > 0 && cursize > 0, "Read first() from empty Buffer");
		return vctr[start];
	}
	
	// Access the last item in array
	const RtpStreamSend::BufferItem& RtpStreamSend::Buffer::last() const
	{
		MS_ASSERT(vctr.size() > 0 && maxsize > 0  && cursize > 0, "Read last() from empty Buffer");
		return vctr[(start + cursize) % vctr.size()]; 
	}

	// Access an item in vctr[] by index relative to start.
	RtpStreamSend::BufferItem& RtpStreamSend::Buffer::operator[] (size_t index)
	{
		MS_ASSERT(index <= maxsize, "index out of vector maxsize capacity");
		
		auto idx = vctr.empty() ? start + index : (start + index) % vctr.size();
		return vctr[idx];
	}

	// Access an item in vctr[] by packet's sequence id - if it present
	RtpStreamSend::BufferItem* RtpStreamSend::Buffer::getbyseq(uint16_t seq)
	{
		if (vctr.empty()) return nullptr;

		for (size_t idx = 0; idx < cursize; idx++)
		{
			auto currentSeq = (*this)[idx-1].seq;
			if (seq == currentSeq) {
				return &((*this)[idx]);
			}
		}

		return nullptr;
	}

	// Add new item at the end, if there is room
	bool RtpStreamSend::Buffer::push_back(const RtpStreamSend::BufferItem& val)
	{
		// can't insert, no room in array
		if (cursize >= maxsize + 1)
			return false;
		
		auto idx = vctr.empty() ? start : (start + cursize) % vctr.size();
		vctr[idx] = val;
		cursize++;

		return true;
	}

	// Remove the first item from array
	void RtpStreamSend::Buffer::trim_front()
	{
		if (empty())
			return;
		
		(*this)[start].packet = nullptr;
		start = (start + 1) % vctr.size();
		cursize--;
	}

	// Inserts data into a buffer so newer packets with higher BufferItem::seq placed are at the end
	// Returns a pointer to newly added item, or nullptr if packet with the same seq was already stored
	RtpStreamSend::BufferItem* RtpStreamSend::Buffer::ordered_insert_by_seq(const RtpStreamSend::BufferItem& val)
	{
		MS_ASSERT(cursize <= maxsize, "Buffer exceeded max capacity, must trim it prior to inserting new items");
		MS_ASSERT(cursize > 0, "ordered_insert_by_seq should only be called when there is at least one item in array");

		// idx is a position of the "hole" between array elements. 
		// Inserted packets will be put in there
		size_t idx = cursize;
		auto packetSeq = val.seq;
		RtpStreamSend::BufferItem* retItem = { nullptr };

		// First, insert new packet in buffer array unless already stored.
		// Later we will check if buffer array went beyond max capacity and in that case remove the oldest packet
		for (; idx > 0; idx--)
		{
			auto currentSeq = (*this)[idx-1].seq;

			// Packet is already stored, nothing to do but shift all items back to the left
			if (packetSeq == currentSeq) {
				for (auto j = idx; j < cursize; j++ ) {	// j indicates the location of a "hole" slot, we want to move the "hole" to the very right position
					(*this)[j] = (*this)[j + 1];
					(*this)[j + 1].packet = nullptr;
				}
				break;
			}

			if (RTC::SeqManager<uint16_t>::IsSeqHigherThan(packetSeq, currentSeq))
			{
				// insert here.
				(*this)[idx] = val;
				retItem = &((*this)[idx]);
				break;
			}

			// Shift current buffer item into an empty slot on the right, so the "hole" moves to the left
			// Then either we insert a new packet in place of "hole" on the next iteration, or will iterate further
			(*this)[idx] = (*this)[idx - 1];
			(*this)[idx - 1].packet = nullptr;
		}

		return retItem;
	}

	/* Instance methods. */

	RtpStreamSend::RtpStreamSend(
	  RTC::RtpStreamSend::Listener* listener, RTC::RtpStream::Params& params, size_t bufferSize)
	  : RTC::RtpStream::RtpStream(listener, params, 10), storage(bufferSize), buffer(bufferSize)
	{
		MS_TRACE();
	}

	RtpStreamSend::~RtpStreamSend()
	{
		MS_TRACE();

		// Clear the RTP buffer.
		ClearRetransmissionBuffer();
	}

	void RtpStreamSend::FillJsonStats(json& jsonObject)
	{
		MS_TRACE();

		uint64_t now = DepLibUV::GetTime();

		RTC::RtpStream::FillJsonStats(jsonObject);

		jsonObject["timestamp"]     = now;
		jsonObject["type"]          = "outbound-rtp";
		jsonObject["roundTripTime"] = this->rtt;
		jsonObject["packetCount"]   = this->transmissionCounter.GetPacketCount();
		jsonObject["byteCount"]     = this->transmissionCounter.GetBytes();
		jsonObject["bitrate"]       = this->transmissionCounter.GetBitrate(now);
	}

	bool RtpStreamSend::ReceivePacket(RTC::RtpPacket* packet)
	{
		MS_TRACE();

		// Call the parent method.
		if (!RtpStream::ReceivePacket(packet))
			return false;

		// If it's a key frame clear the RTP retransmission buffer to avoid
		// congesting the receiver by sending useless retransmissions (now that we
		// are sending a newer key frame).
		if (packet->IsKeyFrame())
			ClearRetransmissionBuffer();

		// If bufferSize was given, store the packet into the buffer.
		if (!this->storage.empty())
			StorePacket(packet);

		// Increase transmission counter.
		this->transmissionCounter.Update(packet);

		return true;
	}

	void RtpStreamSend::ReceiveNack(RTC::RTCP::FeedbackRtpNackPacket* nackPacket)
	{
		MS_TRACE();

		this->nackCount++;

		for (auto it = nackPacket->Begin(); it != nackPacket->End(); ++it)
		{
			RTC::RTCP::FeedbackRtpNackItem* item = *it;

			this->nackPacketCount += item->CountRequestedPackets();

			FillRetransmissionContainer(item->GetPacketId(), item->GetLostPacketBitmask());

			for (auto seqid : RetransmissionContainer)
			{
				auto* bufferItem = this->buffer.getbyseq(seqid);
				if (bufferItem == nullptr)
					break;

				// Note that this is an already RTX encoded packet if RTX is used
				// (FillRetransmissionContainer() did it).
				auto* packet = bufferItem->packet;

				// Retransmit the packet.
				static_cast<RTC::RtpStreamSend::Listener*>(this->listener)
				  ->OnRtpStreamRetransmitRtpPacket(this, packet);

				// Mark the packet as retransmitted.
				RTC::RtpStream::PacketRetransmitted(packet);

				// Mark the packet as repaired (only if this is the first retransmission).
				if (bufferItem->sentTimes == 1)
					RTC::RtpStream::PacketRepaired(packet);
			}
		}
	}

	void RtpStreamSend::ReceiveKeyFrameRequest(RTC::RTCP::FeedbackPs::MessageType messageType)
	{
		MS_TRACE();

		switch (messageType)
		{
			case RTC::RTCP::FeedbackPs::MessageType::PLI:
				this->pliCount++;
				break;

			case RTC::RTCP::FeedbackPs::MessageType::FIR:
				this->firCount++;
				break;

			default:;
		}
	}

	void RtpStreamSend::ReceiveRtcpReceiverReport(RTC::RTCP::ReceiverReport* report)
	{
		MS_TRACE();

		/* Calculate RTT. */

		// Get the NTP representation of the current timestamp.
		uint64_t now = DepLibUV::GetTime();
		auto ntp     = Utils::Time::TimeMs2Ntp(now);

		// Get the compact NTP representation of the current timestamp.
		uint32_t compactNtp = (ntp.seconds & 0x0000FFFF) << 16;

		compactNtp |= (ntp.fractions & 0xFFFF0000) >> 16;

		uint32_t lastSr = report->GetLastSenderReport();
		uint32_t dlsr   = report->GetDelaySinceLastSenderReport();

		// RTT in 1/2^16 second fractions.
		uint32_t rtt{ 0 };

		if (compactNtp > dlsr + lastSr)
			rtt = compactNtp - dlsr - lastSr;
		else
			rtt = 0;

		// RTT in milliseconds.
		this->rtt = (rtt >> 16) * 1000;
		this->rtt += (static_cast<float>(rtt & 0x0000FFFF) / 65536) * 1000;

		this->packetsLost  = report->GetTotalLost();
		this->fractionLost = report->GetFractionLost();

		// Update the score with the received RR.
		UpdateScore(report);
	}

	RTC::RTCP::SenderReport* RtpStreamSend::GetRtcpSenderReport(uint64_t now)
	{
		MS_TRACE();

		if (this->transmissionCounter.GetPacketCount() == 0u)
			return nullptr;

		auto ntp    = Utils::Time::TimeMs2Ntp(now);
		auto report = new RTC::RTCP::SenderReport();

		report->SetSsrc(GetSsrc());
		report->SetPacketCount(this->transmissionCounter.GetPacketCount());
		report->SetOctetCount(this->transmissionCounter.GetBytes());
		report->SetRtpTs(this->maxPacketTs);
		report->SetNtpSec(ntp.seconds);
		report->SetNtpFrac(ntp.fractions);

		return report;
	}

	RTC::RTCP::SdesChunk* RtpStreamSend::GetRtcpSdesChunk()
	{
		MS_TRACE();

		auto& cname     = GetCname();
		auto* sdesChunk = new RTC::RTCP::SdesChunk(GetSsrc());
		auto* sdesItem =
		  new RTC::RTCP::SdesItem(RTC::RTCP::SdesItem::Type::CNAME, cname.size(), cname.c_str());

		sdesChunk->AddItem(sdesItem);

		return sdesChunk;
	}

	void RtpStreamSend::Pause()
	{
		MS_TRACE();

		ClearRetransmissionBuffer();
	}

	void RtpStreamSend::Resume()
	{
		MS_TRACE();
	}

	uint32_t RtpStreamSend::GetBitrate(uint64_t /*now*/, uint8_t /*spatialLayer*/, uint8_t /*temporalLayer*/)
	{
		MS_ABORT("Invalid method call");
	}

	uint32_t RtpStreamSend::GetLayerBitrate(
	  uint64_t /*now*/, uint8_t /*spatialLayer*/, uint8_t /*temporalLayer*/)
	{
		MS_ABORT("Invalid method call");
	}

	void RtpStreamSend::ClearRetransmissionBuffer()
	{
		MS_TRACE();

		// Delete cloned packets.
		for (size_t idx = 0; idx < this->buffer.datasize(); idx++)
		{
			delete this->buffer[idx].packet;
		}

		// Clear buffer list.
		this->buffer.clear();
		
		//Clear storage list.
		this->storage.clear();
	}

	void RtpStreamSend::StorePacket(RTC::RtpPacket* packet)
	{
		MS_TRACE();

		if (packet->GetSize() > RTC::MtuSize)
		{
			MS_WARN_TAG(
			  rtp,
			  "packet too big [ssrc:%" PRIu32 ", seq:%" PRIu16 ", size:%zu]",
			  packet->GetSsrc(),
			  packet->GetSequenceNumber(),
			  packet->GetSize());

			return;
		}

		// Sum the packet seq number and the number of 16 bits cycles.
		auto packetSeq = packet->GetSequenceNumber();
		BufferItem bufferItem;

		bufferItem.seq = packetSeq;

		// If empty do it easy.
		if (this->buffer.empty())
		{
			auto store = this->storage[0].store;

			bufferItem.packet = packet->Clone(store);
			this->buffer.push_back(bufferItem);

			return;
		}

		// Otherwise, do the stuff.
		RtpStreamSend::BufferItem* newItem = this->buffer.ordered_insert_by_seq(bufferItem);

		// Packet already stored, nothing to do
		if (newItem == nullptr)
		{
			return;
		}

		uint8_t* store{ nullptr };
		if (this->buffer.datasize() <= this->storage.size())
		{
			store = this->storage[this->buffer.datasize() - 1].store;
		}
		else
		{
			// Otherwise remove the first packet of the buffer and replace its storage area.
			MS_ASSERT(this->buffer.datasize() - 1  == this->storage.size(), "When buffer beyond max capacity storage should be exactly at full capacity");
			auto* firstPacket = this->buffer.first().packet;

			// Store points to the store used by the first packet.
			store = const_cast<uint8_t*>(firstPacket->GetData());
			// Free the first packet.
			delete firstPacket;
			// Remove the first element in the list.
			this->buffer.trim_front();
		}

		// Update the new buffer item so it points to the cloned packed.
		newItem->packet = packet->Clone(store);
	}

	// This method looks for the requested RTP packets and inserts them into the
	// RetransmissionContainer vector (and sets to null the next position).
	//
	// If RTX is used the stored packet will be RTX encoded now (if not already
	// encoded in a previous resend).
	void RtpStreamSend::FillRetransmissionContainer(uint16_t seq, uint16_t bitmask)
	{
		MS_TRACE();

		// Ensure the container's first element is 0.
		RetransmissionContainer[0] = 0;

		// If NACK is not supported, exit.
		if (!this->params.useNack)
		{
			MS_WARN_TAG(rtx, "NACK not supported");

			return;
		}

		// If the buffer is empty just return.
		if (this->buffer.empty())
			return;

		uint16_t firstSeq       = seq;
		uint16_t lastSeq        = firstSeq + MaxRequestedPackets - 1;
		uint16_t bufferFirstSeq = this->buffer.first().seq;
		uint16_t bufferLastSeq  = this->buffer.last().seq;

		// Requested packet range not found.
		if (
		  RTC::SeqManager<uint16_t>::IsSeqHigherThan(firstSeq, bufferLastSeq) ||
		  RTC::SeqManager<uint16_t>::IsSeqLowerThan(lastSeq, bufferFirstSeq))
		{
			MS_WARN_TAG(
			  rtx,
			  "requested packet range not in the buffer [seq:%" PRIu16 ", bufferFirstseq:%" PRIu16
			  ", bufferLastseq:%" PRIu16 "]",
			  seq,
			  bufferFirstSeq,
			  bufferLastSeq);

			return;
		}

		// Look for each requested packet.
		uint64_t now = DepLibUV::GetTime();
		uint16_t rtt = (this->rtt != 0u ? this->rtt : DefaultRtt);
		bool requested{ true };
		size_t containerIdx{ 0 };

		// Some variables for debugging.
		uint16_t origBitmask = bitmask;
		uint16_t sentBitmask{ 0b0000000000000000 };
		bool isFirstPacket{ true };
		bool firstPacketSent{ false };
		uint8_t bitmaskCounter{ 0 };
		bool tooOldPacketFound{ false };

		while (requested || bitmask != 0)
		{
			bool sent = false;

			if (requested)
			{
				size_t idx = 0;
				for (; idx < this->buffer.datasize(); idx++)
				{
					auto currentSeq = this->buffer[idx].seq;

					// Found.
					if (currentSeq == seq)
					{
						auto* currentPacket = this->buffer[idx].packet;
						// Calculate how the elapsed time between the max timestampt seen and
						// the requested packet's timestampt (in ms).
						uint32_t diffTs = this->maxPacketTs - currentPacket->GetTimestamp();
						uint32_t diffMs = diffTs * 1000 / this->params.clockRate;

						// Just provide the packet if no older than MaxRetransmissionDelay ms.
						if (diffMs > MaxRetransmissionDelay)
						{
							if (!tooOldPacketFound)
							{
								MS_WARN_TAG(
								  rtx,
								  "ignoring retransmission for too old packet "
								  "[seq:%" PRIu16 ", max age:%" PRIu32 "ms, packet age:%" PRIu32 "ms]",
								  currentPacket->GetSequenceNumber(),
								  MaxRetransmissionDelay,
								  diffMs);

								tooOldPacketFound = true;
							}

							break;
						}

						// Don't resent the packet if it was resent in the last RTT ms.
						auto resentAtTime = this->buffer[idx].resentAtTime;

						if ((resentAtTime != 0u) && now - resentAtTime <= static_cast<uint64_t>(rtt))
						{
							MS_DEBUG_TAG(
							  rtx,
							  "ignoring retransmission for a packet already resent in the last RTT ms "
							  "[seq:%" PRIu16 ", rtt:%" PRIu32 "]",
							  currentPacket->GetSequenceNumber(),
							  rtt);

							break;
						}

						// If we use RTX and the packet has not yet been resent, encode it
						// now.
						if (HasRtx() && !this->buffer[idx].rtxEncoded)
						{
							currentPacket->RtxEncode(
							  this->params.rtxPayloadType, this->params.rtxSsrc, ++this->rtxSeq);

							this->buffer[idx].rtxEncoded = true;
						}

						// Store the buffer item in the container and then increment its index.
						RetransmissionContainer[containerIdx++] = this->buffer[idx].seq;

						// Save when this packet was resent.
						this->buffer[idx].resentAtTime = now;

						// Increase the number of times this packet was sent.
						this->buffer[idx].sentTimes++;

						sent = true;

						if (isFirstPacket)
							firstPacketSent = true;

						break;
					}

					// It can not be after this packet.
					if (RTC::SeqManager<uint16_t>::IsSeqHigherThan(currentSeq, seq))
						break;
				}
			}

			requested = (bitmask & 1) != 0;
			bitmask >>= 1;
			++seq;

			if (!isFirstPacket)
			{
				sentBitmask |= (sent ? 1 : 0) << bitmaskCounter;
				++bitmaskCounter;
			}
			else
			{
				isFirstPacket = false;
			}
		}

		// If not all the requested packets were sent, log it.
		if (!firstPacketSent || origBitmask != sentBitmask)
		{
			MS_DEBUG_TAG(
			  rtx,
			  "could not resend all packets [seq:%" PRIu16
			  ", first:%s, "
			  "bitmask:" MS_UINT16_TO_BINARY_PATTERN ", sent bitmask:" MS_UINT16_TO_BINARY_PATTERN "]",
			  seq,
			  firstPacketSent ? "yes" : "no",
			  MS_UINT16_TO_BINARY(origBitmask),
			  MS_UINT16_TO_BINARY(sentBitmask));
		}
		else
		{
			MS_DEBUG_TAG(
			  rtx,
			  "all packets resent [seq:%" PRIu16 ", bitmask:" MS_UINT16_TO_BINARY_PATTERN "]",
			  seq,
			  MS_UINT16_TO_BINARY(origBitmask));
		}

		// Set the next container element to null.
		RetransmissionContainer[containerIdx] = 0;
	}

	void RtpStreamSend::UpdateScore(RTC::RTCP::ReceiverReport* report)
	{
		MS_TRACE();

		// Calculate number of packets sent in this interval.
		auto totalSent = this->transmissionCounter.GetPacketCount();
		auto sent      = totalSent - this->sentPrior;

		this->sentPrior = totalSent;

		// Calculate number of packets lost in this interval.
		uint32_t totalLost = report->GetTotalLost() > 0 ? report->GetTotalLost() : 0;
		uint32_t lost;

		if (totalLost < this->lostPrior)
			lost = 0;
		else
			lost = totalLost - this->lostPrior;

		this->lostPrior = totalLost;

		// Calculate number of packets repaired in this interval.
		auto totalRepaired = this->packetsRepaired;
		uint32_t repaired  = totalRepaired - this->repairedPrior;

		this->repairedPrior = totalRepaired;

		// Calculate number of packets retransmitted in this interval.
		auto totatRetransmitted = this->packetsRetransmitted;
		uint32_t retransmitted  = totatRetransmitted - this->retransmittedPrior;

		this->retransmittedPrior = totatRetransmitted;

		// We didn't send any packet.
		if (sent == 0)
		{
			RTC::RtpStream::UpdateScore(10);

			return;
		}

		if (lost > sent)
			lost = sent;

		if (repaired > lost)
		{
			if (HasRtx())
			{
				repaired = lost;
				retransmitted -= repaired - lost;
			}
			else
			{
				lost = repaired;
			}
		}

#ifdef MS_LOG_DEV
		MS_DEBUG_TAG(
		  score,
		  "[totalSent:%zu, totalLost:%" PRIi32 ", totalRepaired:%zu",
		  totalSent,
		  totalLost,
		  totalRepaired);

		MS_DEBUG_TAG(
		  score,
		  "fixed values [sent:%zu, lost:%" PRIu32 ", repaired:%" PRIu32 ", retransmitted:%" PRIu32,
		  sent,
		  lost,
		  repaired,
		  retransmitted);
#endif

		float repairedRatio = static_cast<float>(repaired) / static_cast<float>(sent);
		auto repairedWeight = std::pow(1 / (repairedRatio + 1), 4);

		MS_ASSERT(retransmitted >= repaired, "repaired packets cannot be more than retransmitted ones");

		if (retransmitted > 0)
			repairedWeight *= repaired / retransmitted;

		lost -= repaired * repairedWeight;

		float deliveredRatio = static_cast<float>(sent - lost) / static_cast<float>(sent);
		auto score           = std::round(std::pow(deliveredRatio, 4) * 10);

#ifdef MS_LOG_DEV
		MS_DEBUG_TAG(
		  score,
		  "[deliveredRatio:%f, repairedRatio:%f, repairedWeight:%f, new lost:%" PRIu32 ", score: %lf]",
		  deliveredRatio,
		  repairedRatio,
		  repairedWeight,
		  lost,
		  score);
#endif

		RtpStream::UpdateScore(score);
	}
} // namespace RTC
