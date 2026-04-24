from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

WHITELIST = [
    "00:00:00:00:00:01",
    "00:00:00:00:00:02"
]


def _handle_PacketIn(event):
    packet = event.parsed
    src = str(packet.src)

    if src not in WHITELIST:
        log.info("🚫 BLOCKED: %s", src)
        return

    log.info("✅ ALLOWED: %s", src)

    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)


def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Access Control Controller Started 🚀")
