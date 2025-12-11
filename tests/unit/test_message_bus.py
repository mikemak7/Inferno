"""Unit tests for MessageBus."""

import asyncio
from datetime import datetime

import pytest

from inferno.swarm.message_bus import (
    MessageBus,
    AgentMessage,
    MessageType,
    MessageHandler,
    get_message_bus,
    reset_message_bus,
)


@pytest.fixture
async def message_bus():
    """Create a message bus for testing."""
    bus = MessageBus(max_queue_size=100)
    await bus.start()
    yield bus
    await bus.stop()
    await reset_message_bus()


@pytest.fixture
def sample_message():
    """Create a sample message."""
    return AgentMessage(
        message_id="test_001",
        sender_agent="agent_a",
        recipient_agent="agent_b",
        message_type=MessageType.FINDING,
        payload={"test": "data"},
        timestamp=datetime.utcnow(),
        priority=50,
    )


class TestAgentMessage:
    """Test AgentMessage class."""

    def test_message_creation(self, sample_message):
        """Test message creation with valid data."""
        assert sample_message.message_id == "test_001"
        assert sample_message.sender_agent == "agent_a"
        assert sample_message.recipient_agent == "agent_b"
        assert sample_message.message_type == MessageType.FINDING
        assert sample_message.priority == 50

    def test_invalid_priority(self):
        """Test that invalid priority raises error."""
        with pytest.raises(ValueError, match="Priority must be 0-100"):
            AgentMessage(
                message_id="test",
                sender_agent="a",
                recipient_agent="b",
                message_type=MessageType.FINDING,
                payload={},
                timestamp=datetime.utcnow(),
                priority=150,  # Invalid
            )

    def test_invalid_payload_type(self):
        """Test that non-dict payload raises error."""
        with pytest.raises(TypeError, match="Payload must be dict"):
            AgentMessage(
                message_id="test",
                sender_agent="a",
                recipient_agent="b",
                message_type=MessageType.FINDING,
                payload="not a dict",  # Invalid
                timestamp=datetime.utcnow(),
            )


class TestMessageBus:
    """Test MessageBus functionality."""

    @pytest.mark.asyncio
    async def test_bus_start_stop(self):
        """Test starting and stopping the bus."""
        bus = MessageBus()
        assert not bus._running

        await bus.start()
        assert bus._running

        await bus.stop()
        assert not bus._running

    @pytest.mark.asyncio
    async def test_publish_direct_message(self, message_bus, sample_message):
        """Test publishing a direct message."""
        received_messages = []

        async def handler(msg: AgentMessage):
            received_messages.append(msg)

        await message_bus.subscribe("agent_b", handler)
        await message_bus.publish(sample_message)

        # Wait for processing
        await asyncio.sleep(0.1)

        assert len(received_messages) == 1
        assert received_messages[0].message_id == "test_001"

    @pytest.mark.asyncio
    async def test_broadcast_message(self, message_bus):
        """Test broadcasting to all agents."""
        received_by_a = []
        received_by_b = []

        async def handler_a(msg: AgentMessage):
            received_by_a.append(msg)

        async def handler_b(msg: AgentMessage):
            received_by_b.append(msg)

        await message_bus.subscribe("agent_a", handler_a)
        await message_bus.subscribe("agent_b", handler_b)

        # Broadcast message (recipient_agent=None)
        broadcast_msg = AgentMessage(
            message_id="broadcast_001",
            sender_agent="agent_c",
            recipient_agent=None,  # Broadcast
            message_type=MessageType.STATUS,
            payload={"status": "ready"},
            timestamp=datetime.utcnow(),
        )
        await message_bus.publish(broadcast_msg)

        await asyncio.sleep(0.1)

        # Both agents should receive (but not sender)
        assert len(received_by_a) == 1
        assert len(received_by_b) == 1

    @pytest.mark.asyncio
    async def test_message_type_filtering(self, message_bus):
        """Test filtering messages by type."""
        findings_received = []
        all_received = []

        async def finding_handler(msg: AgentMessage):
            findings_received.append(msg)

        async def all_handler(msg: AgentMessage):
            all_received.append(msg)

        # Subscribe with type filter
        await message_bus.subscribe(
            "agent_a",
            finding_handler,
            message_types={MessageType.FINDING},
        )
        await message_bus.subscribe("agent_a", all_handler)

        # Send FINDING message
        finding_msg = AgentMessage(
            message_id="f001",
            sender_agent="sender",
            recipient_agent="agent_a",
            message_type=MessageType.FINDING,
            payload={},
            timestamp=datetime.utcnow(),
        )
        await message_bus.publish(finding_msg)

        # Send STATUS message
        status_msg = AgentMessage(
            message_id="s001",
            sender_agent="sender",
            recipient_agent="agent_a",
            message_type=MessageType.STATUS,
            payload={},
            timestamp=datetime.utcnow(),
        )
        await message_bus.publish(status_msg)

        await asyncio.sleep(0.1)

        # Finding handler should only receive FINDING
        assert len(findings_received) == 1
        assert findings_received[0].message_type == MessageType.FINDING

        # All handler receives both
        assert len(all_received) == 2

    @pytest.mark.asyncio
    async def test_priority_filtering(self, message_bus):
        """Test filtering messages by priority."""
        high_priority_received = []

        async def high_priority_handler(msg: AgentMessage):
            high_priority_received.append(msg)

        # Subscribe with priority threshold
        await message_bus.subscribe(
            "agent_a",
            high_priority_handler,
            priority_threshold=70,
        )

        # Send low priority message
        low_msg = AgentMessage(
            message_id="low",
            sender_agent="sender",
            recipient_agent="agent_a",
            message_type=MessageType.STATUS,
            payload={},
            timestamp=datetime.utcnow(),
            priority=50,
        )
        await message_bus.publish(low_msg)

        # Send high priority message
        high_msg = AgentMessage(
            message_id="high",
            sender_agent="sender",
            recipient_agent="agent_a",
            message_type=MessageType.STATUS,
            payload={},
            timestamp=datetime.utcnow(),
            priority=80,
        )
        await message_bus.publish(high_msg)

        await asyncio.sleep(0.1)

        # Should only receive high priority
        assert len(high_priority_received) == 1
        assert high_priority_received[0].priority == 80

    @pytest.mark.asyncio
    async def test_broadcast_finding(self, message_bus):
        """Test convenience method for broadcasting findings."""
        received = []

        async def handler(msg: AgentMessage):
            received.append(msg)

        await message_bus.subscribe("agent_a", handler)

        finding = {"type": "sqli", "severity": "high"}
        await message_bus.broadcast_finding("scanner", finding, priority=75)

        await asyncio.sleep(0.1)

        assert len(received) == 1
        assert received[0].message_type == MessageType.FINDING
        assert received[0].payload["finding"]["type"] == "sqli"
        assert received[0].priority == 75

    @pytest.mark.asyncio
    async def test_request_response(self, message_bus):
        """Test request/response correlation."""
        # Setup responder
        async def responder(msg: AgentMessage):
            if msg.message_type == MessageType.REQUEST:
                # Send response
                response = AgentMessage(
                    message_id="response_001",
                    sender_agent="agent_b",
                    recipient_agent=msg.sender_agent,
                    message_type=MessageType.RESPONSE,
                    payload={"context": "data"},
                    timestamp=datetime.utcnow(),
                    correlation_id=msg.message_id,
                )
                await message_bus.publish(response)

        await message_bus.subscribe("agent_b", responder)

        # Request context
        result = await message_bus.request_context(
            requester="agent_a",
            target_agent="agent_b",
            context_type="test_context",
            timeout_seconds=2.0,
        )

        assert result["context"] == "data"

    @pytest.mark.asyncio
    async def test_request_timeout(self, message_bus):
        """Test request timeout when no response."""
        # No responder registered
        with pytest.raises(asyncio.TimeoutError):
            await message_bus.request_context(
                requester="agent_a",
                target_agent="agent_b",
                context_type="test",
                timeout_seconds=0.5,
            )

    @pytest.mark.asyncio
    async def test_send_status(self, message_bus):
        """Test sending status updates."""
        received = []

        async def handler(msg: AgentMessage):
            received.append(msg)

        await message_bus.subscribe("agent_a", handler)

        await message_bus.send_status(
            "agent_b",
            "scanning",
            metadata={"progress": 0.5},
        )

        await asyncio.sleep(0.1)

        assert len(received) == 1
        assert received[0].message_type == MessageType.STATUS
        assert received[0].payload["status"] == "scanning"

    @pytest.mark.asyncio
    async def test_unsubscribe(self, message_bus):
        """Test unsubscribing an agent."""
        received = []

        async def handler(msg: AgentMessage):
            received.append(msg)

        await message_bus.subscribe("agent_a", handler)
        await message_bus.unsubscribe("agent_a")

        msg = AgentMessage(
            message_id="test",
            sender_agent="sender",
            recipient_agent="agent_a",
            message_type=MessageType.STATUS,
            payload={},
            timestamp=datetime.utcnow(),
        )
        await message_bus.publish(msg)

        await asyncio.sleep(0.1)

        # Should not receive after unsubscribe
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_get_stats(self, message_bus):
        """Test getting bus statistics."""
        async def handler(msg: AgentMessage):
            pass

        await message_bus.subscribe("agent_a", handler)

        msg = AgentMessage(
            message_id="test",
            sender_agent="sender",
            recipient_agent="agent_a",
            message_type=MessageType.STATUS,
            payload={},
            timestamp=datetime.utcnow(),
        )
        await message_bus.publish(msg)

        stats = message_bus.get_stats()
        assert stats["total_messages"] == 1
        assert stats["active_agents"] == 1

    @pytest.mark.asyncio
    async def test_publish_without_start(self):
        """Test that publishing without starting raises error."""
        bus = MessageBus()
        msg = AgentMessage(
            message_id="test",
            sender_agent="a",
            recipient_agent="b",
            message_type=MessageType.STATUS,
            payload={},
            timestamp=datetime.utcnow(),
        )

        with pytest.raises(RuntimeError, match="not running"):
            await bus.publish(msg)

    @pytest.mark.asyncio
    async def test_handler_error_handling(self, message_bus):
        """Test that handler errors don't crash the bus."""

        async def faulty_handler(msg: AgentMessage):
            raise ValueError("Handler error")

        await message_bus.subscribe("agent_a", faulty_handler)

        msg = AgentMessage(
            message_id="test",
            sender_agent="sender",
            recipient_agent="agent_a",
            message_type=MessageType.STATUS,
            payload={},
            timestamp=datetime.utcnow(),
        )

        # Should not raise
        await message_bus.publish(msg)
        await asyncio.sleep(0.1)


def test_global_singleton():
    """Test global message bus singleton."""
    bus1 = get_message_bus()
    bus2 = get_message_bus()
    assert bus1 is bus2
