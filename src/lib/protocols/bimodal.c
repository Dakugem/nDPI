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
    u_int32_t range_896_1024;
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
    NDPI_LOG_DBG(ndpi_struct, "BIMODAL dissector called\n");

    /*if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
    {
        printf("Resetting previously detected protocol: %d\n", flow->detected_protocol_stack[0]);
        flow->detected_protocol_stack[0] = NDPI_PROTOCOL_UNKNOWN;
        flow->confidence = NDPI_CONFIDENCE_UNKNOWN;
    }*/

    struct ndpi_packet_struct *packet = &ndpi_struct->packet;

    // Проверяем базовые условия
    if (packet->udp == NULL || packet->payload_packet_len == 0 || packet->payload_packet_len >= 1025)
    {
        NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
        return;
    }

    // Инициализируем статистику при первом пакете
    if (!flow->l4.udp.bimodal_stats)
    {
        init_bimodal_stats(flow);
        if (!flow->l4.udp.bimodal_stats)
        {
            NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
            return;
        }
    }


    struct bimodal_flow_stats *stats = (struct bimodal_flow_stats *)flow->l4.udp.bimodal_stats;
    u_int16_t pkt_len = packet->payload_packet_len;

    // Обновляем статистику
    stats->total_packets++;

    // Классификация по длине пакета (исправлен последний диапазон)
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
    else if (pkt_len <= 1024)
        stats->range_896_1024++;

    // Проверяем детекцию каждые 10 пакетов после первых 10
    if (stats->total_packets >= 10 && (stats->total_packets % 10 == 0))
    {
        float total = (float)stats->total_packets;
        float ratio_short = (float)(stats->range_1_127) / total;
        float ratio_mid_short = (float)(stats->range_128_255 + stats->range_256_383) / total;
        float ratio_mid = (float)(stats->range_384_511 + stats->range_512_639) / total;
        float ratio_mid_long = (float)(stats->range_640_767 + stats->range_768_895) / total;
        float ratio_long = (float)(stats->range_896_1024) / total;

        NDPI_LOG_INFO(ndpi_struct,
                      "[BIMODAL] Checking: packets=%u, short=%.3f, mid_short=%.3f, mid=%.3f, mid_long=%.3f, long=%.3f\n",
                      stats->total_packets, ratio_short, ratio_mid_short, ratio_mid, ratio_mid_long, ratio_long);

        int bimodal_score = 0;

        // Критерий 1: наличие пиков в коротких и длинных пакетах
        if (ratio_short >= 0.15f && ratio_long >= 0.15f)
        {
            bimodal_score += 2;
            NDPI_LOG_DBG(ndpi_struct, "[BIMODAL] Passed peaks criterion\n");
        }

        // Критерий 2: определенная доля почти средних пакетов
        if (ratio_mid_short + ratio_mid_long <= 0.5f)
        {
            bimodal_score++;
            NDPI_LOG_DBG(ndpi_struct, "[BIMODAL] Passed low middle criterion\n");
        }

        // Критерий 3: определенная доля средних пакетов
        if (ratio_mid <= 0.2f)
        {
            bimodal_score++;
            NDPI_LOG_DBG(ndpi_struct, "[BIMODAL] Passed low middle criterion\n");
        }

        // Детектируем если набрали достаточно баллов
        if (bimodal_score >= 3)
        {
            NDPI_LOG_INFO(ndpi_struct,
                          "[BIMODAL] DETECTED! Score=%d, packets=%u, ratios: S=%.3f, MS=%.3f, M=%.3f, ML=%.3f, L=%.3f\n",
                          bimodal_score, stats->total_packets, ratio_short, ratio_mid_short, ratio_mid, ratio_mid_long, ratio_long);

            ndpi_set_detected_protocol(ndpi_struct, flow,
                                       NDPI_PROTOCOL_BIMODAL,
                                       NDPI_PROTOCOL_UNKNOWN,
                                       NDPI_CONFIDENCE_DPI);
            free_bimodal_stats(flow);
            return;
        }
        else
        {
            NDPI_LOG_DBG(ndpi_struct, "[BIMODAL] Not detected, score=%d\n", bimodal_score);
        }
    }

    // Если прошло много пакетов и не детектировали - исключаем
    if (stats->total_packets > 2000)
    {
        NDPI_LOG_DBG(ndpi_struct, "[BIMODAL] Excluding after %u packets\n", stats->total_packets);
        NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
        free_bimodal_stats(flow);
    }
}

// Функция инициализации протокола
void init_bimodal_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
    register_dissector("BIMODAL", ndpi_struct,
                       ndpi_search_bimodal,
                       NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                       1, NDPI_PROTOCOL_BIMODAL);
}

/*void init_bimodal_detector(struct ndpi_detection_module_struct *ndpi_struct)
{
    printf("=== INITIALIZING BIMODAL DETECTOR ===\n");

    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);

    // Устанавливаем детектор для всех протоколов
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);
}*/