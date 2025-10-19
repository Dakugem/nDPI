#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_BIMODAL

#include "ndpi_api.h"
#include "ndpi_private.h"

// Структура для хранения статистики потока
struct bimodal_flow_stats
{
    u_int32_t total_packets;
    u_int32_t range_1_127;
    u_int32_t range_128_255;
    u_int32_t range_256_383;
    u_int32_t range_384_511;
    u_int32_t range_512_639;
    u_int32_t range_640_767;
    u_int32_t range_768_895;
    u_int32_t range_896_1023;
    u_int32_t last_detection_check;
};

// Инициализация статистики
static void init_bimodal_stats(struct ndpi_flow_struct *flow)
{
    struct bimodal_flow_stats *stats = ndpi_malloc(sizeof(struct bimodal_flow_stats));
    if (stats)
    {
        memset(stats, 0, sizeof(struct bimodal_flow_stats));
        flow->l4.udp.bimodal_stats = stats;
    }
}

// Освобождение памяти
static void free_bimodal_stats(struct ndpi_flow_struct *flow)
{
    if (flow->l4.udp.bimodal_stats)
    {
        ndpi_free(flow->l4.udp.bimodal_stats);
        flow->l4.udp.bimodal_stats = NULL;
    }
}

// Функция детекции
static void ndpi_search_bimodal(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;

    NDPI_LOG_DBG(ndpi_struct, "search BIMODAL\n");

    if (packet->udp == NULL)
    {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
    }

    if (packet->payload_packet_len == 0)
    {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
    }

    // Инициализируем статистику при первом пакете
    if (!flow->l4.udp.bimodal_stats)
    {
        init_bimodal_stats(flow);
        if (!flow->l4.udp.bimodal_stats)
        {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
        }
    }

    struct bimodal_flow_stats *stats = (struct bimodal_flow_stats *)flow->l4.udp.bimodal_stats;
    u_int16_t pkt_len = packet->payload_packet_len;

    // Обновляем статистику
    stats->total_packets++;

    // Классификация по длине пакета
    if (pkt_len <= 127)
        stats->range_1_127++;
    else if (pkt_len <= 255)
        stats->range_128_255++;
    else if (pkt_len <= 383)
        stats->range_256_383++;
    else if (pkt_len <= 511)
        stats->range_384_511++;
    else if (pkt_len <= 639)
        stats->range_512_639++;
    else if (pkt_len <= 767)
        stats->range_640_767++;
    else if (pkt_len <= 895)
        stats->range_768_895++;
    else if (pkt_len <= 1023)
        stats->range_896_1023++;

    // Проверяем детекцию каждые 500 пакетов после первых 1000
    if (stats->total_packets >= 1000 && (stats->total_packets % 500 == 0))
    {
        float ratio_short = (float)(stats->range_1_127) / stats->total_packets;
        float ratio_mid_short = (float)(stats->range_128_255 + stats->range_256_383) / stats->total_packets;
        float ratio_mid = (float)(stats->range_384_511 + stats->range_512_639) / stats->total_packets;
        float ratio_mid_long  = (float)(stats->range_640_767 + stats->range_768_895) / stats->total_packets;
        float ratio_long  = (float)(stats->range_896_1023) / stats->total_packets;

        // Критерии бимодального распределения
        if (ratio_short >= 0.22f &&   
            ratio_mid_short <= 0.27f &&    
            ratio_mid <= 0.2f &&
            ratio_mid_long <= 0.27f &&
            ratio_long >= 0.22f)
        { 

            /* This looks BIMODAL */
            NDPI_LOG_INFO(ndpi_struct, "[BIMODAL] Detected custom protocol: short=%.2f, mid_short=%.2f, mid=%.2f, mid_long=%.2f, long=%.2f\n",
                          ratio_short, ratio_mid_short, ratio_mid, ratio_mid_long, ratio_long);

            ndpi_set_detected_protocol(ndpi_struct, flow,
                                       NDPI_PROTOCOL_BIMODAL,
                                       NDPI_PROTOCOL_UNKNOWN);
            free_bimodal_stats(flow);
            return;
        }
    }

    // Если прошло много пакетов и не детектировали - исключаем
    if (stats->total_packets > 5000)
    {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        free_bimodal_stats(flow);
    }
    return;
}

// Функция инициализации протокола
void init_bimodal_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
    register_dissector("BIMODAL", ndpi_struct,
                       ndpi_search_bimodal,
                       NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                       1, NDPI_PROTOCOL_BIMODAL);

    ndpi_struct->proto_defaults[NDPI_PROTOCOL_BIMODAL].funcs.flow_free = free_bimodal_stats;
}