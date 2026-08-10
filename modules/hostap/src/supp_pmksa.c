/*
 * Copyright (c) 2026 Siddhant Modi
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "supp_pmksa.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include "includes.h"
#include "common.h"
#include "common/defs.h"
#include "wpa_supplicant/config.h"
#include "wpa_supplicant_i.h"
#include "wpa.h"
#include "pmksa_cache.h"

/* Mirrors hostap's private limit; imports at capacity can evict oldest idle entries. */
#define SUPP_PMKSA_CACHE_MAX_ENTRIES 32U
#define PMKSA_CACHE_ADDED_EVENT      "PMKSA-CACHE-ADDED"
#define PMKSA_CACHE_REMOVED_EVENT    "PMKSA-CACHE-REMOVED"

static int supplicant_pmksa_akm_to_hostap(enum wifi_akm_suite akm, int *akmp)
{
	if (akmp == NULL) {
		return -EINVAL;
	}

	switch (akm) {
	case WIFI_AKM_SUITE_802_1X:
		*akmp = WPA_KEY_MGMT_IEEE8021X;
		break;
	case WIFI_AKM_SUITE_PSK:
		*akmp = WPA_KEY_MGMT_PSK;
		break;
	case WIFI_AKM_SUITE_FT_802_1X:
		*akmp = WPA_KEY_MGMT_FT_IEEE8021X;
		break;
	case WIFI_AKM_SUITE_FT_PSK:
		*akmp = WPA_KEY_MGMT_FT_PSK;
		break;
	case WIFI_AKM_SUITE_802_1X_SHA256:
		*akmp = WPA_KEY_MGMT_IEEE8021X_SHA256;
		break;
	case WIFI_AKM_SUITE_PSK_SHA256:
		*akmp = WPA_KEY_MGMT_PSK_SHA256;
		break;
	case WIFI_AKM_SUITE_SAE:
		*akmp = WPA_KEY_MGMT_SAE;
		break;
	case WIFI_AKM_SUITE_FT_SAE:
		*akmp = WPA_KEY_MGMT_FT_SAE;
		break;
	case WIFI_AKM_SUITE_802_1X_SUITE_B:
		*akmp = WPA_KEY_MGMT_IEEE8021X_SUITE_B;
		break;
	case WIFI_AKM_SUITE_802_1X_SUITE_B_192:
		*akmp = WPA_KEY_MGMT_IEEE8021X_SUITE_B_192;
		break;
	case WIFI_AKM_SUITE_FT_802_1X_SHA384:
		*akmp = WPA_KEY_MGMT_FT_IEEE8021X_SHA384;
		break;
	case WIFI_AKM_SUITE_FILS_SHA256:
		*akmp = WPA_KEY_MGMT_FILS_SHA256;
		break;
	case WIFI_AKM_SUITE_FILS_SHA384:
		*akmp = WPA_KEY_MGMT_FILS_SHA384;
		break;
	case WIFI_AKM_SUITE_FT_FILS_SHA256:
		*akmp = WPA_KEY_MGMT_FT_FILS_SHA256;
		break;
	case WIFI_AKM_SUITE_FT_FILS_SHA384:
		*akmp = WPA_KEY_MGMT_FT_FILS_SHA384;
		break;
	case WIFI_AKM_SUITE_OWE:
		*akmp = WPA_KEY_MGMT_OWE;
		break;
	case WIFI_AKM_SUITE_802_1X_SHA384:
		*akmp = WPA_KEY_MGMT_IEEE8021X_SHA384;
		break;
	case WIFI_AKM_SUITE_SAE_EXT_KEY:
		*akmp = WPA_KEY_MGMT_SAE_EXT_KEY;
		break;
	case WIFI_AKM_SUITE_FT_SAE_EXT_KEY:
		*akmp = WPA_KEY_MGMT_FT_SAE_EXT_KEY;
		break;
	case WIFI_AKM_SUITE_DPP:
	default:
		return -EPROTONOSUPPORT;
	}

	return 0;
}

static int supplicant_pmksa_akm_from_hostap(int akmp, enum wifi_akm_suite *akm)
{
	if (akm == NULL) {
		return -EINVAL;
	}

	switch (akmp) {
	case WPA_KEY_MGMT_IEEE8021X:
		*akm = WIFI_AKM_SUITE_802_1X;
		break;
	case WPA_KEY_MGMT_PSK:
		*akm = WIFI_AKM_SUITE_PSK;
		break;
	case WPA_KEY_MGMT_FT_IEEE8021X:
		*akm = WIFI_AKM_SUITE_FT_802_1X;
		break;
	case WPA_KEY_MGMT_FT_PSK:
		*akm = WIFI_AKM_SUITE_FT_PSK;
		break;
	case WPA_KEY_MGMT_IEEE8021X_SHA256:
		*akm = WIFI_AKM_SUITE_802_1X_SHA256;
		break;
	case WPA_KEY_MGMT_PSK_SHA256:
		*akm = WIFI_AKM_SUITE_PSK_SHA256;
		break;
	case WPA_KEY_MGMT_SAE:
		*akm = WIFI_AKM_SUITE_SAE;
		break;
	case WPA_KEY_MGMT_FT_SAE:
		*akm = WIFI_AKM_SUITE_FT_SAE;
		break;
	case WPA_KEY_MGMT_IEEE8021X_SUITE_B:
		*akm = WIFI_AKM_SUITE_802_1X_SUITE_B;
		break;
	case WPA_KEY_MGMT_IEEE8021X_SUITE_B_192:
		*akm = WIFI_AKM_SUITE_802_1X_SUITE_B_192;
		break;
	case WPA_KEY_MGMT_FT_IEEE8021X_SHA384:
		*akm = WIFI_AKM_SUITE_FT_802_1X_SHA384;
		break;
	case WPA_KEY_MGMT_FILS_SHA256:
		*akm = WIFI_AKM_SUITE_FILS_SHA256;
		break;
	case WPA_KEY_MGMT_FILS_SHA384:
		*akm = WIFI_AKM_SUITE_FILS_SHA384;
		break;
	case WPA_KEY_MGMT_FT_FILS_SHA256:
		*akm = WIFI_AKM_SUITE_FT_FILS_SHA256;
		break;
	case WPA_KEY_MGMT_FT_FILS_SHA384:
		*akm = WIFI_AKM_SUITE_FT_FILS_SHA384;
		break;
	case WPA_KEY_MGMT_OWE:
		*akm = WIFI_AKM_SUITE_OWE;
		break;
	case WPA_KEY_MGMT_IEEE8021X_SHA384:
		*akm = WIFI_AKM_SUITE_802_1X_SHA384;
		break;
	case WPA_KEY_MGMT_SAE_EXT_KEY:
		*akm = WIFI_AKM_SUITE_SAE_EXT_KEY;
		break;
	case WPA_KEY_MGMT_FT_SAE_EXT_KEY:
		*akm = WIFI_AKM_SUITE_FT_SAE_EXT_KEY;
		break;
	default:
		return -EPROTONOSUPPORT;
	}

	return 0;
}

static bool supplicant_pmksa_is_suite_b(int akmp)
{
	return akmp == WPA_KEY_MGMT_IEEE8021X_SUITE_B || akmp == WPA_KEY_MGMT_IEEE8021X_SUITE_B_192;
}

static bool supplicant_pmksa_is_ft_eap(int akmp)
{
	return akmp == WPA_KEY_MGMT_FT_IEEE8021X || akmp == WPA_KEY_MGMT_FT_IEEE8021X_SHA384;
}

static int supplicant_pmksa_check_pmk_len(int akmp, size_t pmk_len)
{
	bool sha384 = akmp == WPA_KEY_MGMT_IEEE8021X_SUITE_B_192 ||
		      akmp == WPA_KEY_MGMT_FILS_SHA384 || akmp == WPA_KEY_MGMT_FT_FILS_SHA384 ||
		      akmp == WPA_KEY_MGMT_FT_IEEE8021X_SHA384 ||
		      akmp == WPA_KEY_MGMT_IEEE8021X_SHA384;
	bool variable_length = akmp == WPA_KEY_MGMT_OWE || akmp == WPA_KEY_MGMT_SAE_EXT_KEY ||
			       akmp == WPA_KEY_MGMT_FT_SAE_EXT_KEY;

	if (variable_length) {
		return pmk_len == 32U || pmk_len == 48U || pmk_len == 64U ? 0 : -EPROTONOSUPPORT;
	}

	if (sha384) {
		return pmk_len == 48U ? 0 : -EPROTONOSUPPORT;
	}

	return pmk_len == 32U ? 0 : -EPROTONOSUPPORT;
}

bool supplicant_pmksa_policy_allows(bool ft_eap_pmksa_caching, int akmp)
{
	return !supplicant_pmksa_is_ft_eap(akmp) || ft_eap_pmksa_caching;
}

static int supplicant_pmksa_add_time(os_time_t now, uint32_t delta, os_time_t *result)
{
	if (result == NULL || now < 0 || (uint64_t)now > INT64_MAX - delta) {
		return -EINVAL;
	}

	*result = now + delta;
	return 0;
}

static int supplicant_pmksa_remaining_time(os_time_t expiration, os_time_t now, uint32_t *remaining)
{
	if (remaining == NULL || expiration <= now) {
		return -ENOENT;
	}

	if ((uint64_t)(expiration - now) > UINT32_MAX) {
		return -EPROTONOSUPPORT;
	}

	*remaining = expiration - now;
	return 0;
}

int supplicant_pmksa_entry_from_wifi(const struct wifi_pmksa_cache_entry *source, void *network_ctx,
				     bool ft_eap_pmksa_caching, const uint8_t *expected_spa,
				     const struct os_reltime *now,
				     struct rsn_pmksa_cache_entry *destination)
{
	int akmp;

	if (source == NULL || network_ctx == NULL || expected_spa == NULL || now == NULL ||
	    destination == NULL || source->pmk_len > WIFI_PMKSA_PMK_MAX_LEN) {
		return -EINVAL;
	}
	if (memcmp(source->spa, expected_spa, ETH_ALEN) != 0) {
		return -EINVAL;
	}
	if (supplicant_pmksa_akm_to_hostap(source->akm, &akmp) != 0 ||
	    !supplicant_pmksa_policy_allows(ft_eap_pmksa_caching, akmp) ||
	    (source->opportunistic && supplicant_pmksa_is_suite_b(akmp))) {
		return -EPROTONOSUPPORT;
	}
	if (supplicant_pmksa_check_pmk_len(akmp, source->pmk_len) != 0) {
		return -EPROTONOSUPPORT;
	}

	memset(destination, 0, sizeof(*destination));
	if (supplicant_pmksa_add_time(now->sec, source->expiration_remaining_s,
				      &destination->expiration) != 0 ||
	    supplicant_pmksa_add_time(now->sec, source->reauth_remaining_s,
				      &destination->reauth_time) != 0) {
		memset(destination, 0, sizeof(*destination));
		return -EINVAL;
	}

	memcpy(destination->aa, source->bssid, ETH_ALEN);
	memcpy(destination->spa, source->spa, ETH_ALEN);
	memcpy(destination->pmkid, source->pmkid, PMKID_LEN);
	memcpy(destination->pmk, source->pmk, source->pmk_len);
	destination->pmk_len = source->pmk_len;
	destination->akmp = akmp;
	destination->network_ctx = network_ctx;
	destination->external = true;
	destination->fils_cache_id_set = source->fils_cache_id_set;
	if (source->fils_cache_id_set) {
		memcpy(destination->fils_cache_id, source->fils_cache_id, FILS_CACHE_ID_LEN);
	}
	destination->opportunistic = source->opportunistic;

	return 0;
}

int supplicant_pmksa_entry_to_wifi(const struct rsn_pmksa_cache_entry *source,
				   const void *network_ctx, bool ft_eap_pmksa_caching,
				   const struct os_reltime *now,
				   struct wifi_pmksa_cache_entry *destination)
{
	enum wifi_akm_suite akm;
	uint32_t expiration;
	int ret;

	if (destination == NULL) {
		return -EINVAL;
	}
	wifi_pmksa_cache_entries_clear(destination, 1U);
	if (source == NULL || network_ctx == NULL || now == NULL) {
		return -EINVAL;
	}
	if (source->network_ctx != network_ctx || source->expiration <= now->sec) {
		return -ENOENT;
	}
	ret = supplicant_pmksa_akm_from_hostap(source->akmp, &akm);
	if (ret != 0 || !supplicant_pmksa_policy_allows(ft_eap_pmksa_caching, source->akmp) ||
	    (source->opportunistic && supplicant_pmksa_is_suite_b(source->akmp))) {
		return -EPROTONOSUPPORT;
	}
	ret = supplicant_pmksa_check_pmk_len(source->akmp, source->pmk_len);
	if (ret != 0) {
		return ret;
	}
	ret = supplicant_pmksa_remaining_time(source->expiration, now->sec, &expiration);
	if (ret != 0) {
		return ret;
	}

	destination->expiration_remaining_s = expiration;
	destination->reauth_remaining_s =
		source->reauth_time <= now->sec
			? 0U
			: (uint32_t)MIN((uint64_t)(source->reauth_time - now->sec), UINT32_MAX);
	destination->reauth_remaining_s = MIN(destination->reauth_remaining_s, expiration);
	destination->akm = akm;
	destination->pmk_len = source->pmk_len;
	memcpy(destination->pmkid, source->pmkid, PMKID_LEN);
	memcpy(destination->pmk, source->pmk, source->pmk_len);
	memcpy(destination->bssid, source->aa, ETH_ALEN);
	memcpy(destination->spa, source->spa, ETH_ALEN);
	destination->fils_cache_id_set = source->fils_cache_id_set;
	if (source->fils_cache_id_set) {
		memcpy(destination->fils_cache_id, source->fils_cache_id, FILS_CACHE_ID_LEN);
	}
	destination->opportunistic = source->opportunistic;

	return 0;
}

static bool supplicant_pmksa_entry_is_eligible(const struct rsn_pmksa_cache_entry *entry,
					       const void *network_ctx, bool ft_eap_pmksa_caching,
					       const struct os_reltime *now)
{
	enum wifi_akm_suite akm;

	return entry != NULL && entry->network_ctx == network_ctx && entry->expiration > now->sec &&
	       supplicant_pmksa_akm_from_hostap(entry->akmp, &akm) == 0 &&
	       supplicant_pmksa_policy_allows(ft_eap_pmksa_caching, entry->akmp) &&
	       !(entry->opportunistic && supplicant_pmksa_is_suite_b(entry->akmp)) &&
	       supplicant_pmksa_check_pmk_len(entry->akmp, entry->pmk_len) == 0;
}

int supplicant_pmksa_query_entries(const struct rsn_pmksa_cache_entry *head,
				   const void *network_ctx, bool ft_eap_pmksa_caching,
				   const struct os_reltime *now,
				   struct wifi_pmksa_cache_query *query)
{
	const struct rsn_pmksa_cache_entry *entry;
	uint32_t eligible = 0U;
	int ret = -ENOENT;

	if (query == NULL) {
		return -EINVAL;
	}
	wifi_pmksa_cache_entries_clear(&query->entry, 1U);
	query->entry_count = 0U;
	if (network_ctx == NULL || now == NULL) {
		return -EINVAL;
	}

	for (entry = head; entry != NULL; entry = entry->next) {
		if (!supplicant_pmksa_entry_is_eligible(entry, network_ctx, ft_eap_pmksa_caching,
							now)) {
			continue;
		}
		if (eligible == query->index) {
			ret = supplicant_pmksa_entry_to_wifi(
				entry, network_ctx, ft_eap_pmksa_caching, now, &query->entry);
		}
		eligible++;
	}
	query->entry_count = eligible;
	return query->index < eligible ? ret : -ENOENT;
}

int supplicant_pmksa_event_command(const char *text, enum net_event_wifi_cmd *event)
{
	if (text == NULL || event == NULL) {
		return -EINVAL;
	}

	if (strncmp(text, PMKSA_CACHE_ADDED_EVENT, sizeof(PMKSA_CACHE_ADDED_EVENT) - 1U) == 0) {
		*event = NET_EVENT_WIFI_CMD_PMKSA_CACHE_ADDED;
		return 0;
	}
	if (strncmp(text, PMKSA_CACHE_REMOVED_EVENT, sizeof(PMKSA_CACHE_REMOVED_EVENT) - 1U) == 0) {
		*event = NET_EVENT_WIFI_CMD_PMKSA_CACHE_REMOVED;
		return 0;
	}

	return -EINVAL;
}

int supplicant_pmksa_parse_event(const char *text, struct wifi_pmksa_cache_event *event,
				 int *network_id)
{
	char type[32];
	char bssid[18];
	int id;
	int consumed;

	if (text == NULL || event == NULL || network_id == NULL ||
	    sscanf(text, "%31s %17s %d %n", type, bssid, &id, &consumed) != 3 ||
	    text[consumed] != '\0' || id < 0 ||
	    (strcmp(type, PMKSA_CACHE_ADDED_EVENT) != 0 &&
	     strcmp(type, PMKSA_CACHE_REMOVED_EVENT) != 0) ||
	    hwaddr_aton(bssid, event->bssid) != 0) {
		return -EINVAL;
	}

	*network_id = id;
	return 0;
}

#if defined(CONFIG_WIFI_MGMT_PMKSA_IMPORT)
enum wifi_pmksa_cache_usage
supplicant_pmksa_usage_result(bool entries_supplied, bool connection_succeeded,
			      const struct rsn_pmksa_cache_entry *current)
{
	if (!entries_supplied) {
		return WIFI_PMKSA_CACHE_USAGE_NOT_ATTEMPTED;
	}
	if (!connection_succeeded) {
		return WIFI_PMKSA_CACHE_USAGE_UNKNOWN;
	}
	return current != NULL && current->external ? WIFI_PMKSA_CACHE_USAGE_HIT
						    : WIFI_PMKSA_CACHE_USAGE_MISS;
}

static void supplicant_pmksa_free_entry(struct rsn_pmksa_cache_entry *entry)
{
	if (entry != NULL) {
		bin_clear_free(entry, sizeof(*entry));
	}
}

int supplicant_pmksa_import_entries(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
				    const struct wifi_pmksa_cache_entry *entries,
				    size_t entry_count)
{
	struct rsn_pmksa_cache_entry **converted = NULL;
	struct rsn_pmksa_cache_entry *existing;
	struct os_reltime now;
	size_t i;
	int ret = 0;

	if (wpa_s == NULL || wpa_s->wpa == NULL || ssid == NULL ||
	    (entry_count != 0U && entries == NULL)) {
		return -EINVAL;
	}
	if (wpa_sm_get_pmksa_cache(wpa_s->wpa) == NULL) {
		return -ENOTSUP;
	}
	if (entry_count > SUPP_PMKSA_CACHE_MAX_ENTRIES) {
		return -ENOSPC;
	}
	if (entry_count == 0U) {
		return 0;
	}

	os_get_reltime(&now);
	converted = os_calloc(entry_count, sizeof(*converted));
	if (converted == NULL) {
		return -ENOMEM;
	}
	for (i = 0; i < entry_count; i++) {
		for (size_t j = 0; j < i; j++) {
			if (memcmp(entries[i].bssid, entries[j].bssid, ETH_ALEN) == 0 &&
			    memcmp(entries[i].spa, entries[j].spa, ETH_ALEN) == 0) {
				ret = -EEXIST;
				goto fail;
			}
		}
		converted[i] = os_zalloc(sizeof(*converted[i]));
		if (converted[i] == NULL) {
			ret = -ENOMEM;
			goto fail;
		}
		ret = supplicant_pmksa_entry_from_wifi(&entries[i], ssid,
						       ssid->ft_eap_pmksa_caching, wpa_s->own_addr,
						       &now, converted[i]);
		if (ret != 0) {
			goto fail;
		}
	}

	for (i = 0; i < entry_count; i++) {
		for (existing = wpa_sm_pmksa_cache_head(wpa_s->wpa); existing != NULL;
		     existing = existing->next) {
			if (memcmp(existing->aa, converted[i]->aa, ETH_ALEN) == 0 &&
			    memcmp(existing->spa, converted[i]->spa, ETH_ALEN) == 0) {
				if (existing->pmk_len == converted[i]->pmk_len &&
				    memcmp(existing->pmk, converted[i]->pmk, existing->pmk_len) ==
					    0 &&
				    memcmp(existing->pmkid, converted[i]->pmkid, PMKID_LEN) == 0) {
					wpa_sm_pmksa_cache_remove(wpa_s->wpa, existing);
				}
				break;
			}
		}
		(void)wpa_sm_pmksa_cache_add_entry(wpa_s->wpa, converted[i]);
		converted[i] = NULL;
	}

	os_free(converted);
	return 0;

fail:
	for (i = 0; i < entry_count; i++) {
		supplicant_pmksa_free_entry(converted[i]);
	}
	os_free(converted);
	return ret;
}

void supplicant_pmksa_flush_external_locked(struct wpa_supplicant *wpa_s, void *network_ctx)
{
	if (wpa_s != NULL && wpa_s->wpa != NULL) {
		wpa_sm_external_pmksa_cache_flush(wpa_s->wpa, network_ctx);
	}
}
#endif /* CONFIG_WIFI_MGMT_PMKSA_IMPORT */
