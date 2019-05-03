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
	// Don't retransmit packets older than this (ms).
	static constexpr uint32_t MaxRetransmissionDelay{ 2000 };
	static constexpr uint32_t DefaultRtt{ 100 };

	/* Instance methods. */

	const RtpStreamSend::BufferItem& RtpStreamSend::Buffer::First() const
	{
		MS_TRACE();

		MS_ASSERT(
		  this->vctr.size() > 0 && this->maxSize > 0 && this->currentSize > 0,
		  "Must not read First() from empty Buffer");

		return this->vctr[this->startIdx];
	}

	const RtpStreamSend::BufferItem& RtpStreamSend::Buffer::Last() const
	{
		MS_TRACE();

		MS_ASSERT(
		  this->vctr.size() > 0 && this->maxSize > 0 && this->currentSize > 0,
		  "Must not read Last() from empty Buffer");

		return this->vctr[(this->startIdx + this->currentSize) % this->vctr.size() - 1];
	}

	RtpStreamSend::BufferItem& RtpStreamSend::Buffer::operator[](size_t idx)
	{
		MS_TRACE();

		MS_ASSERT(idx <= this->maxSize, "idx out of vector maxSize capacity");

		idx = this->vctr.empty() ? this->startIdx + idx : (this->startIdx + idx) % this->vctr.size();

		return this->vctr[idx];
	}

	RtpStreamSend::BufferItem* RtpStreamSend::Buffer::GetBySeq(uint16_t seq)
	{
		MS_TRACE();

		if (this->vctr.empty())
			return nullptr;

		for (size_t idx{ 0 }; idx < this->currentSize; ++idx)
		{
			auto currentSeq = (*this)[idx].seq;
			if (seq == currentSeq)
				return std::addressof((*this)[idx]);
		}

		return nullptr;
	}

	bool RtpStreamSend::Buffer::PushBack(const RtpStreamSend::BufferItem& item)
	{
		MS_TRACE();

		// No room.
		if (this->currentSize > this->maxSize)
			return false;

		auto idx = this->vctr.empty() ? this->startIdx
		                              : (this->startIdx + this->currentSize) % this->vctr.size();

		this->vctr[idx] = item;
		this->currentSize++;

		return true;
	}

	void RtpStreamSend::Buffer::TrimFront()
	{
		MS_TRACE();

		if (Empty())
			return;

		this->vctr[this->startIdx].packet = nullptr;
		this->startIdx                    = (this->startIdx + 1) % this->vctr.size();
		this->currentSize--;
	}

	RtpStreamSend::BufferItem* RtpStreamSend::Buffer::OrderedInsertBySeq(
	  const RtpStreamSend::BufferItem& item)
	{
		MS_TRACE();

		MS_ASSERT(
		  this->currentSize <= this->maxSize,
		  "Buffer exceeded max capacity, must trim it prior to inserting new items");
		MS_ASSERT(
		  this->currentSize > 0, "should only be called when there is at least one item the Buffer");

		// idx is a position of the "hole" between vector elements. Inserted packets
		// will be put in there.
		size_t idx     = this->currentSize;
		auto packetSeq = item.seq;
		RtpStreamSend::BufferItem* retItem{ nullptr };

		// First, insert new packet in the vector unless already stored. Later we will
		// check if vector went beyond max capacity and in that case remove the oldest
		// packet.
		for (; idx > 0; --idx)
		{
			// TODO: Why idx - 1?
			auto currentSeq = (*this)[idx - 1].seq;

			// Packet is already stored, nothing to do but shift all items back to the
			// left.
			if (packetSeq == currentSeq)
			{
				MS_ERROR("--- duplicated packet, seq:%" PRIu16 ", idx:%zu", packetSeq, idx);

				// j indicates the location of a "hole" slot, we want to move the "hole"
				// to the very right position.
				for (size_t j{ idx }; j < this->currentSize; ++j)
				{
					(*this)[j]            = (*this)[j + 1];
					(*this)[j + 1].packet = nullptr;
				}

				break;
			}

			if (RTC::SeqManager<uint16_t>::IsSeqHigherThan(packetSeq, currentSeq))
			{
				MS_ERROR("--- storing item, seq:%" PRIu16 ", idx:%zu", packetSeq, idx);

				// Insert here.
				(*this)[idx] = item;
				this->currentSize++;

				retItem = std::addressof((*this)[idx]);

				break;
			}

			// Shift current item into an empty slot on the right so the "hole" moves
			// to the left. Then either we insert a new packet in place of "hole" on
			// the next iteration or will iterate further.
			(*this)[idx]            = (*this)[idx - 1];
			(*this)[idx - 1].packet = nullptr;

			// Special case: we want to insert the oldest packet in the first position
			// unless doing this will put buffer over capacity,
			// then we do nothing but ensure that "hole" is back to the very right.
			if (idx == 1)
			{
				if (this->currentSize < this->maxSize)
				{
					MS_ERROR("--- adding item in front, seq:%" PRIu16, packetSeq);
					// Insert in front
					this->startIdx = this->vctr.empty() ? this->startIdx
		                              : (this->startIdx - 1) % this->vctr.size();

					this->vctr[this->startIdx] = item;
					this->currentSize++;

					retItem = std::addressof((*this)[0]);

					break;
				}
				else {
					this->startIdx = (this->startIdx + 1) % this->vctr.size();
				}
			}
		}
		return retItem;
	}

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

			// Container to be filled with the sequence numbers of packets to be
			// retransmitted.
			// TODO: if new packets are not inserted into this->buffer between a call to FillRetransmissionContainer and packets retransmission,
			// seqs vector can contain memory locations to BufferItem instead of seq ids, making GetBySeq() obsolete.
			std::vector<uint16_t> seqs;

			seqs.reserve(MaxRequestedPackets + 1);

			FillRetransmissionContainer(item->GetPacketId(), item->GetLostPacketBitmask(), seqs);

				MS_ERROR("--- seqs.size():%zu", seqs.size());

			for (auto seq : seqs)
			{
				auto* bufferItem = this->buffer.GetBySeq(seq);

				// TODO: Temporal.
				MS_ASSERT(bufferItem != nullptr, "bufferItem cannot be nullptr");

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
		for (size_t idx{ 0 }; idx < this->buffer.GetSize(); ++idx)
		{
			delete this->buffer[idx].packet;
		}

		// Clear buffer.
		this->buffer.Clear();

		// Clear storage.
		this->storage.clear();
	}

	void RtpStreamSend::StorePacket(RTC::RtpPacket* packet)
	{
		MS_TRACE();

		MS_ERROR("packet->GetSequenceNumber():%" PRIu16, packet->GetSequenceNumber());

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

		auto packetSeq = packet->GetSequenceNumber();
		BufferItem bufferItem;

		bufferItem.seq = packetSeq;

		// If empty do it easy.
		if (this->buffer.Empty())
		{
			MS_ERROR("buffer.Empty(), seq:%" PRIu16, bufferItem.seq);

			auto store = this->storage[0].store;

			bufferItem.packet = packet->Clone(store);
			this->buffer.PushBack(bufferItem);

			return;
		}

		uint8_t* store{ nullptr };

		// Should first try inserting an item, and then trimming extra packet
		// because OrderedInsertBySeq() does not guarantee to increate number of buffer items (duplicates).
		// For this reason there is always an extra storage space for a single packet
		auto* newItem = this->buffer.OrderedInsertBySeq(bufferItem);
		if (newItem)
			MS_ERROR("newItem.seq:%" PRIu16, newItem->seq);
		else
			MS_ERROR("newItem:nullptr");

		// Packet already stored, nothing to do.
		if (newItem == nullptr)
			return;

		if (this->buffer.GetSize() <= this->storage.size())
		{
			MS_ERROR("--- this->buffer.GetSize() <= this->storage.size()");

			store = this->storage[this->buffer.GetSize() - 1].store;
		}
		else
		{
			MS_ERROR("--- this->buffer.GetSize() > this->storage.size()");

			// Otherwise remove the first oldest packet of the buffer and replace its storage area.
			MS_ASSERT(
			  this->buffer.GetSize() - 1 == this->storage.size(),
			  "when buffer has just exceeded max capacity, storage should be exactly at full capacity");

			auto* firstPacket = this->buffer.First().packet;

			// Store points to the store used by the first packet.
			store = const_cast<uint8_t*>(firstPacket->GetData());

			// Free the first packet.
			delete firstPacket;

			// Remove the first element in the buffer.
			this->buffer.TrimFront();
		}

		// Update the new buffer item so it points to the cloned packed.
		newItem->packet = packet->Clone(store);


		// TODO
		MS_ERROR("<this->buffer.vctr>");
		for (auto& item : this->buffer.vctr)
		{
			MS_ERROR("  item.seq:%" PRIu16, item.seq);
		}
		MS_ERROR("</this->buffer.vctr>");
	}

	// This method looks for the requested RTP packets and inserts them into the
	// given container.
	//
	// If RTX is used the stored packet will be RTX encoded now (if not already
	// encoded in a previous resend).
	void RtpStreamSend::FillRetransmissionContainer(
	  uint16_t seq, uint16_t bitmask, std::vector<uint16_t>& seqs)
	{
		MS_TRACE();

		// If NACK is not supported, exit.
		if (!this->params.useNack)
		{
			MS_WARN_TAG(rtx, "NACK not supported");

			return;
		}

		// If the buffer is empty just return.
		if (this->buffer.Empty())
			return;

		uint16_t firstSeq       = seq;
		uint16_t lastSeq        = firstSeq + MaxRequestedPackets - 1;
		uint16_t bufferFirstSeq = this->buffer.First().seq;
		uint16_t bufferLastSeq  = this->buffer.Last().seq;

		// Requested packet range not found.
		// clang-format off
		if (
			RTC::SeqManager<uint16_t>::IsSeqHigherThan(firstSeq, bufferLastSeq) ||
			RTC::SeqManager<uint16_t>::IsSeqLowerThan(lastSeq, bufferFirstSeq)
		)
		// clang-format on
		{
			MS_WARN_TAG(
			  rtx,
			  "requested packet range not in the buffer [seq:%" PRIu16 ", bufferFirstSeq:%" PRIu16
			  ", bufferLastSeq:%" PRIu16 "]",
			  seq,
			  bufferFirstSeq,
			  bufferLastSeq);

			// TODO
			MS_ERROR(
			  "requested packet range not in the buffer [seq:%" PRIu16 ", bufferFirstSeq:%" PRIu16
			  ", bufferLastSeq:%" PRIu16 "]",
			  seq,
			  bufferFirstSeq,
			  bufferLastSeq);

			return;
		}

		// Look for each requested packet.
		uint64_t now = DepLibUV::GetTime();
		uint16_t rtt = (this->rtt != 0u ? this->rtt : DefaultRtt);
		bool requested{ true };

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
				for (size_t idx{ 0 }; idx < this->buffer.GetSize(); ++idx)
				{
					MS_ERROR("_____(iterating buffer)______ idx:%zu, buffer.GetSize():%zu", idx, this->buffer.GetSize());

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

						MS_ERROR("seqs.push_back(), seq:%" PRIu16 ", idx:%zu", this->buffer[idx].seq, idx);

						// Store the buffer item in the given seq numbers container.
						seqs.push_back(this->buffer[idx].seq);

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

		// If not all the requested packets was sent, log it.
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
