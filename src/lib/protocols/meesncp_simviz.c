#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MEESNCP_SIMVIZ

#include "ndpi_api.h"
#include "ndpi_private.h"

enum ReqResType
{
    Unknown,
    None,
    Tick,
    Reload,
    Create,
    Modify,
    Drag,
    Delete,
    Get_w_Tick,
    Get_wo_Tick,
    Error = 255
};

const char *action_to_str(enum ReqResType action)
{
    switch (action)
    {
    case Unknown:
        return "Unknown";
        break;
    case None:
        return "None";
        break;
    case Tick:
        return "Tick";
        break;
    case Reload:
        return "Reload";
        break;
    case Create:
        return "Create";
        break;
    case Modify:
        return "Modify";
        break;
    case Drag:
        return "Drag";
        break;
    case Delete:
        return "Delete";
        break;
    case Get_w_Tick:
        return "Get_w_Tick";
        break;
    case Get_wo_Tick:
        return "Get_w_oTick";
        break;
    case Error:
        return "Error";
        break;
    default:
        break;
    }
}

// Функция детекции
static void ndpi_search_meesncp_simviz(struct ndpi_detection_module_struct *ndpi_struct,
                                       struct ndpi_flow_struct *flow)
{
    NDPI_LOG_DBG(ndpi_struct, "MEESNCP_SIMVIZ dissector called\n");

    struct ndpi_packet_struct *packet = &ndpi_struct->packet;

    // Проверяем базовые условия
    if (packet->udp == NULL || packet->payload_packet_len == 0)
    {
        NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
        return;
    }

    enum ReqResType action = packet->payload[0];
    size_t len = packet->payload_packet_len;

    bool detected = false;
    bool not_meesncp = false;
    switch (action)
    {
    case Unknown:
        if (len > 1)
            not_meesncp = true;
        break;
    case None:
        if (len > 1)
        {
            not_meesncp = true;
            break;
        }

        detected = true;
        break;
    case Tick:
        if (len % 4 != 1)
        {
            not_meesncp = true;
            break;
        }

        for (size_t i = 3; i < len; i += 4)
        {
            if (packet->payload[i] > 8)
                not_meesncp = true;
        }

        detected = true;
        break;
    case Reload:
        if (len > 2)
            not_meesncp = true;
        break;
    case Create:
        if (len != 10 && len != 75)
        {
            not_meesncp = true;
            break;
        }

        if (packet->payload[8] != 0 && packet->payload[8] != 1 && packet->payload[8] != 16 && packet->payload[8] != 17)
        {
            not_meesncp = true;
            break;
        }

        detected = true;
        break;
    case Modify:
        if (len != 10 && len != 75)
        {
            not_meesncp = true;
            break;
        }

        if (packet->payload[8] != 0 && packet->payload[8] != 1 && packet->payload[8] != 16 && packet->payload[8] != 17)
        {
            not_meesncp = true;
            break;
        }

        detected = true;
        break;
    case Drag:
        if (len != 7)
            not_meesncp = true;
        break;
    case Delete:
        if (len != 3)
            not_meesncp = true;
        break;
    case Get_w_Tick:
        if (len != 3 && (len - 71) % 4 != 0)
        {
            not_meesncp = true;
            break;
        }

        if (len > 3)
        {
            if (packet->payload[3] != 0 && packet->payload[3] != 1 && packet->payload[3] != 16 && packet->payload[3] != 17)
            {
                not_meesncp = true;
                break;
            }
        }

        detected = true;
        break;
    case Get_wo_Tick:
        if (len != 3 && len != 71)
            not_meesncp = true;

        if (len > 3)
        {
            if (packet->payload[3] != 0 && packet->payload[3] != 1 && packet->payload[3] != 16 && packet->payload[3] != 17)
            {
                not_meesncp = true;
                break;
            }
        }

        detected = true;
        break;
    case Error:
        if (len != 2)
        {
            not_meesncp = true;
            break;
        }

        if (packet->payload[1] > 15)
        {
            not_meesncp = true;
            break;
        }

        detected = true;
        break;
    default:
        break;
    }

    if (not_meesncp)
    {
        NDPI_LOG_DBG(ndpi_struct, "[MEESNCP_SIMVIZ] Excluding\n");
        NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    }

    if (detected)
    {
        NDPI_LOG_INFO(ndpi_struct,
                      "[MEESNCP_SIMVIZ] DETECTED with action - %s\n", action_to_str(action));

        ndpi_set_detected_protocol(ndpi_struct, flow,
                                   NDPI_PROTOCOL_MEESNCP_SIMVIZ,
                                   NDPI_PROTOCOL_UNKNOWN,
                                   NDPI_CONFIDENCE_DPI);
    }
}

// Функция инициализации протокола
void init_meesncp_simviz_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
    register_dissector("MEESNCP_SIMVIZ", ndpi_struct,
                       ndpi_search_meesncp_simviz,
                       NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                       1, NDPI_PROTOCOL_MEESNCP_SIMVIZ);
}
