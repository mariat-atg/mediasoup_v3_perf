#ifndef MS_RTC_RTP_STREAM_SEND_HPP
#define MS_RTC_RTP_STREAM_SEND_HPP

#include "Utils.hpp"
#include "RTC/RtpDataCounter.hpp"
#include "RTC/RtpStream.hpp"
#include <list>
#include <vector>

namespace RTC
{
	class RtpStreamSend : public RTC::RtpStream
	{
	public:
		class Listener : public RTC::RtpStream::Listener
		{
		public:
			virtual void OnRtpStreamRetransmitRtpPacket(
			  RTC::RtpStreamSend* rtpStream, RTC::RtpPacket* packet) = 0;
		};

	public:
		struct BufferItem
		{
			uint16_t seq{ 0 }; // RTP seq.
			RTC::RtpPacket* packet{ nullptr };
			uint64_t resentAtTime{ 0 }; // Last time this packet was resent.
			uint8_t sentTimes{ 0 };     // Number of times this packet was resent.
			bool rtxEncoded{ false };   // Whether the packet has already been RTX encoded.
		};

	private:
		struct StorageItem
		{
			// Allow some more space for RTX encoding.
			uint8_t store[RTC::MtuSize + 200];
		};

  private:
	  class Buffer
		{
		private:
			std::vector<BufferItem> vctr; // array that can hold up to maxsize of BufferItems plus 1 empty slot reserved for easier inserts
			uint8_t start{ 0 };           // index in vctr where data begins
			size_t cursize{ 0 };          // number of items currently stored in array. While inserting a new packet, we may see cursize == maxsize + 1 until trim_front() is called
			size_t maxsize{ 0 };          //maximum number of items that can be stored in this Buffer instance

		public:
			Buffer(size_t bufferSize) : vctr(bufferSize + 1), start(0), cursize(0), maxsize(bufferSize) {}
			inline bool empty() const { return vctr.empty() || cursize == 0; }
			inline size_t datasize() const { return vctr.empty() ? 0 : cursize; }

			const RtpStreamSend::BufferItem& first() const;
			const RtpStreamSend::BufferItem& last() const;
			RtpStreamSend::BufferItem& operator[] (size_t index);
			RtpStreamSend::BufferItem* getbyseq(uint16_t seq);

			bool push_back (const RtpStreamSend::BufferItem& val);
			void trim_front();
			RtpStreamSend::BufferItem* ordered_insert_by_seq( const RtpStreamSend::BufferItem& val);
			inline void clear() { vctr.clear(); start = cursize = 0; }
		};

	public:
		RtpStreamSend(
		  RTC::RtpStreamSend::Listener* listener, RTC::RtpStream::Params& params, size_t bufferSize);
		~RtpStreamSend() override;

		void FillJsonStats(json& jsonObject) override;
		void SetRtx(uint8_t payloadType, uint32_t ssrc) override;
		bool ReceivePacket(RTC::RtpPacket* packet) override;
		void ReceiveNack(RTC::RTCP::FeedbackRtpNackPacket* nackPacket);
		void ReceiveKeyFrameRequest(RTC::RTCP::FeedbackPs::MessageType messageType);
		void ReceiveRtcpReceiverReport(RTC::RTCP::ReceiverReport* report);
		RTC::RTCP::SenderReport* GetRtcpSenderReport(uint64_t now);
		RTC::RTCP::SdesChunk* GetRtcpSdesChunk();
		void Pause() override;
		void Resume() override;
		uint32_t GetBitrate(uint64_t now) override;
		uint32_t GetBitrate(uint64_t now, uint8_t spatialLayer, uint8_t temporalLayer) override;
		uint32_t GetLayerBitrate(uint64_t now, uint8_t spatialLayer, uint8_t temporalLayer) override;

	private:
		void StorePacket(RTC::RtpPacket* packet);
		void ClearRetransmissionBuffer();
		void FillRetransmissionContainer(uint16_t seq, uint16_t bitmask);
		void UpdateScore(RTC::RTCP::ReceiverReport* report);

	private:
		uint32_t lostPrior{ 0 }; // Packets lost at last interval.
		uint32_t sentPrior{ 0 }; // Packets sent at last interval.
		std::vector<StorageItem> storage;
		Buffer buffer;
		float rtt{ 0 };
		uint16_t rtxSeq{ 0 };
		RTC::RtpDataCounter transmissionCounter;
	};

	/* Inline instance methods */

	inline void RtpStreamSend::SetRtx(uint8_t payloadType, uint32_t ssrc)
	{
		RTC::RtpStream::SetRtx(payloadType, ssrc);

		this->rtxSeq = Utils::Crypto::GetRandomUInt(0u, 0xFFFF);
	}

	inline uint32_t RtpStreamSend::GetBitrate(uint64_t now)
	{
		return this->transmissionCounter.GetBitrate(now);
	}
} // namespace RTC

#endif
