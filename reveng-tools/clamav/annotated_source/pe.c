extern const unsigned int hashlen[];

struct offset_list {
  uint32_t offset;
  struct offset_list *next;
};

struct pe_image_import_descriptor {
  union {
    uint32_t Characteristics;
    uint32_t OriginalFirstThunk;
  } u;
  uint32_t TimeDateStamp;
  uint32_t ForwarderChain;
  uint32_t Name;
  uint32_t FirstThunk;
};

struct pe_image_thunk32 {
  union {
    uint32_t ForwarderString;
    uint32_t Function;
    uint32_t Ordinal;
    uint32_t AddressOfData;
  } u;
};

struct pe_image_thunk64 {
  union {
    uint64_t ForwarderString;
    uint64_t Function;
    uint64_t Ordinal;
    uint64_t AddressOfData;
  } u;
};

struct pe_image_import_by_name {
  uint16_t Hint;
  uint8_t Name[1];
};

static void cli_multifree(void *f, ...) {
  void *ff;
  va_list ap;
  free(f);

  __builtin_va_start(ap, f);
  while ((ff = __builtin_va_arg(ap, void *)))
    free(ff);

  __builtin_va_end(ap);
}

struct vinfo_list {
  uint32_t rvas[16];
  unsigned int count;
};

static int versioninfo_cb(void *opaque, uint32_t type, uint32_t name,
                          uint32_t lang, uint32_t rva) {
  struct vinfo_list *vlist = (struct vinfo_list *)opaque;

  (!__builtin_expect(!!(cli_debug_flag), 0))
      ? (void)0
      : cli_dbgmsg_internal(
            "versioninfo_cb: type: %x, name: %x, lang: %x, rva: %x\n", type,
            name, lang, rva);
  vlist->rvas[vlist->count] = rva;
  if (++vlist->count == sizeof(vlist->rvas) / sizeof(vlist->rvas[0]))
    return 1;
  return 0;
}

uint32_t cli_rawaddr(uint32_t rva, const struct cli_exe_section *shp,
                     uint16_t nos, unsigned int *err, size_t fsize,
                     uint32_t hdr_size) {
  int i, found = 0;
  uint32_t ret;

  if (rva < hdr_size) {
    if (rva >= fsize) {
      *err = 1;
      return 0;
    }

    *err = 0;
    return rva;
  }

  for (i = nos - 1; i >= 0; i--) {
    if (shp[i].rsz && shp[i].rva <= rva && shp[i].rsz > (rva - shp[i].rva)) {
      found = 1;
      break;
    }
  }

  if (!found) {
    *err = 1;
    return 0;
  }

  ret = (rva - shp[i].rva) + shp[i].raw;
  *err = 0;
  return ret;
}
void findres(uint32_t by_type, uint32_t by_name, fmap_t *map,
             struct cli_exe_info *peinfo,
             int (*cb)(void *, uint32_t, uint32_t, uint32_t, uint32_t),
             void *opaque) {
  unsigned int err = 0;
  uint32_t type, type_offs, name, name_offs, lang, lang_offs;
  const uint8_t *resdir, *type_entry, *name_entry, *lang_entry;
  uint16_t type_cnt, name_cnt, lang_cnt;
  uint32_t res_rva;

  if (((void *)0) == peinfo || peinfo->ndatadirs < 3) {
    return;
  }

  if (0 != peinfo->offset) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("findres: Assumption Violated: Looking for "
                              "version info when peinfo->offset != 0\n");
  }

  res_rva = ((uint32_t)(
      ((const union unaligned_32 *)(&(peinfo->dirs[2].VirtualAddress)))
          ->una_s32));

  if (!(resdir = fmap_need_off_once(map,
                                    cli_rawaddr(res_rva, peinfo->sections,
                                                peinfo->nsections, &err,
                                                map->len, peinfo->hdr_size),
                                    16)) ||
      err)
    return;

  type_cnt = (uint16_t)(((const union unaligned_16 *)(resdir + 12))->una_s16);
  type_entry = resdir + 16;
  if (!(by_type >> 31)) {
    type_entry += type_cnt * 8;
    type_cnt = (uint16_t)(((const union unaligned_16 *)(resdir + 14))->una_s16);
  }

  while (type_cnt--) {
    if (!fmap_need_ptr_once(map, type_entry, 8))
      return;
    type = (((const union unaligned_32 *)(type_entry))->una_s32);
    type_offs = (((const union unaligned_32 *)(type_entry + 4))->una_s32);
    if (type == by_type && (type_offs >> 31)) {
      type_offs &= 0x7fffffff;
      if (!(resdir = fmap_need_off_once(map,
                                        cli_rawaddr(res_rva + type_offs,
                                                    peinfo->sections,
                                                    peinfo->nsections, &err,
                                                    map->len, peinfo->hdr_size),
                                        16)) ||
          err)
        return;

      name_cnt =
          (uint16_t)(((const union unaligned_16 *)(resdir + 12))->una_s16);
      name_entry = resdir + 16;
      if (by_name == 0xffffffff)
        name_cnt +=
            (uint16_t)(((const union unaligned_16 *)(resdir + 14))->una_s16);
      else if (!(by_name >> 31)) {
        name_entry += name_cnt * 8;
        name_cnt =
            (uint16_t)(((const union unaligned_16 *)(resdir + 14))->una_s16);
      }
      while (name_cnt--) {
        if (!fmap_need_ptr_once(map, name_entry, 8))
          return;
        name = (((const union unaligned_32 *)(name_entry))->una_s32);
        name_offs = (((const union unaligned_32 *)(name_entry + 4))->una_s32);
        if ((by_name == 0xffffffff || name == by_name) && (name_offs >> 31)) {
          name_offs &= 0x7fffffff;
          if (!(resdir = fmap_need_off_once(
                    map,
                    cli_rawaddr(res_rva + name_offs, peinfo->sections,
                                peinfo->nsections, &err, map->len,
                                peinfo->hdr_size),
                    16)) ||
              err)
            return;

          lang_cnt =
              (uint16_t)(((const union unaligned_16 *)(resdir + 12))->una_s16) +
              (uint16_t)(((const union unaligned_16 *)(resdir + 14))->una_s16);
          lang_entry = resdir + 16;
          while (lang_cnt--) {
            if (!fmap_need_ptr_once(map, lang_entry, 8))
              return;
            lang = (((const union unaligned_32 *)(lang_entry))->una_s32);
            lang_offs =
                (((const union unaligned_32 *)(lang_entry + 4))->una_s32);
            if (!(lang_offs >> 31)) {
              if (cb(opaque, type, name, lang, res_rva + lang_offs))
                return;
            }
            lang_entry += 8;
          }
        }
        name_entry += 8;
      }
      return;
    }
    type_entry += 8;
  }
}

static void cli_parseres_special(uint32_t base, uint32_t rva, fmap_t *map,
                                 struct cli_exe_info *peinfo, size_t fsize,
                                 unsigned int level, uint32_t type,
                                 unsigned int *maxres,
                                 struct swizz_stats *stats) {
  unsigned int err = 0, i;
  const uint8_t *resdir;
  const uint8_t *entry, *oentry;
  uint16_t named, unnamed;
  uint32_t rawaddr = cli_rawaddr(rva, peinfo->sections, peinfo->nsections, &err,
                                 fsize, peinfo->hdr_size);
  uint32_t entries;

  if (level > 2 || !*maxres)
    return;
  *maxres -= 1;
  if (err || !(resdir = fmap_need_off_once(map, rawaddr, 16)))
    return;
  named = (uint16_t)(((const union unaligned_16 *)(resdir + 12))->una_s16);
  unnamed = (uint16_t)(((const union unaligned_16 *)(resdir + 14))->una_s16);

  entries = unnamed;
  if (!entries)
    return;
  rawaddr += named * 8;

  if (!(entry = fmap_need_off(map, rawaddr + 16, entries * 8))) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_parseres_special: failed to read resource "
                              "directory at:%lu\n",
                              (unsigned long)rawaddr + 16);
    return;
  }
  oentry = entry;
  for (i = 0; i < unnamed; i++, entry += 8) {
    uint32_t id, offs;
    if (stats->errors >= 2000) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_parseres_special: resources broken, ignoring\n");
      return;
    }
    id = (((const union unaligned_32 *)(entry))->una_s32) & 0x7fffffff;
    if (level == 0) {
      type = 0;
      switch (id) {
      case 4:
      case 5:
      case 6:
      case 11:
        type = id;
        break;
      case 16:
        type = id;

        stats->has_version = 1;
        break;
      case 24:
        stats->has_manifest = 1;
        break;
      }
    }
    if (!type) {

      continue;
    }
    offs = (((const union unaligned_32 *)(entry + 4))->una_s32);
    if (offs >> 31)
      cli_parseres_special(base, base + (offs & 0x7fffffff), map, peinfo, fsize,
                           level + 1, type, maxres, stats);
    else {
      offs = (((const union unaligned_32 *)(entry + 4))->una_s32);
      rawaddr = cli_rawaddr(base + offs, peinfo->sections, peinfo->nsections,
                            &err, fsize, peinfo->hdr_size);
      if (!err && (resdir = fmap_need_off_once(map, rawaddr, 16))) {
        uint32_t isz = (((const union unaligned_32 *)(resdir + 4))->una_s32);
        const uint8_t *str;
        rawaddr = cli_rawaddr((((const union unaligned_32 *)(resdir))->una_s32),
                              peinfo->sections, peinfo->nsections, &err, fsize,
                              peinfo->hdr_size);
        if (err || !isz || isz >= fsize || rawaddr + isz >= fsize) {
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("cli_parseres_special: invalid resource "
                                    "table entry: %lu + %lu\n",
                                    (unsigned long)rawaddr, (unsigned long)isz);
          stats->errors++;
          continue;
        }
        if ((id & 0xff) != 0x09)
          continue;
        if ((str = fmap_need_off_once(map, rawaddr, isz)))
          cli_detect_swizz_str(str, isz, stats, type);
      }
    }
  }
  fmap_unneed_ptr(map, oentry, entries * 8);
}

static unsigned int cli_hashsect(fmap_t *map, struct cli_exe_section *s,
                                 unsigned char **digest, int *foundhash,
                                 int *foundwild) {
  const void *hashme;

  if (s->rsz > (182 * 1024 * 1024)) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_hashsect: skipping hash calculation for too big section\n");
    return 0;
  }

  if (!s->rsz)
    return 0;
  if (!(hashme = fmap_need_off_once(map, s->raw, s->rsz))) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_hashsect: unable to read section data\n");
    return 0;
  }

  if (foundhash[CLI_HASH_MD5] || foundwild[CLI_HASH_MD5])
    cl_hash_data("md5", hashme, s->rsz, digest[CLI_HASH_MD5], ((void *)0));
  if (foundhash[CLI_HASH_SHA1] || foundwild[CLI_HASH_SHA1])
    cl_sha1(hashme, s->rsz, digest[CLI_HASH_SHA1], ((void *)0));
  if (foundhash[CLI_HASH_SHA256] || foundwild[CLI_HASH_SHA256])
    cl_sha256(hashme, s->rsz, digest[CLI_HASH_SHA256], ((void *)0));

  return 1;
}

static int scan_pe_mdb(cli_ctx *ctx, struct cli_exe_section *exe_section) {
  struct cli_matcher *mdb_sect = ctx->engine->hm_mdb;
  unsigned char *hashset[CLI_HASH_AVAIL_TYPES];
  const char *virname = ((void *)0);
  int foundsize[CLI_HASH_AVAIL_TYPES];
  int foundwild[CLI_HASH_AVAIL_TYPES];
  enum CLI_HASH_TYPE type;
  int ret = CL_CLEAN;
  unsigned char *md5 = ((void *)0);

  for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
    foundsize[type] = cli_hm_have_size(mdb_sect, type, exe_section->rsz);
    foundwild[type] = cli_hm_have_wild(mdb_sect, type);
    if (foundsize[type] || foundwild[type]) {
      hashset[type] = cli_malloc(hashlen[type]);
      if (!hashset[type]) {
        cli_errmsg("scan_pe_mdb: cli_malloc failed!\n");
        for (; type > 0;)
          free(hashset[--type]);
        return CL_EMEM;
      }
    } else {
      hashset[type] = ((void *)0);
    }
  }

  cli_hashsect(*ctx->fmap, exe_section, hashset, foundsize, foundwild);

  if (cli_debug_flag) {
    md5 = hashset[CLI_HASH_MD5];
    if (md5) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MDB hashset: "
                                "%u:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%"
                                "02x%02x%02x%02x%02x%02x\n",
                                exe_section->rsz, md5[0], md5[1], md5[2],
                                md5[3], md5[4], md5[5], md5[6], md5[7], md5[8],
                                md5[9], md5[10], md5[11], md5[12], md5[13],
                                md5[14], md5[15]);
    } else if (cli_always_gen_section_hash) {
      const void *hashme =
          fmap_need_off_once(*ctx->fmap, exe_section->raw, exe_section->rsz);
      if (!(hashme)) {
        cli_errmsg("scan_pe_mdb: unable to read section data\n");
        ret = CL_EREAD;
        goto end;
      }

      md5 = cli_malloc(16);
      if (!(md5)) {
        cli_errmsg("scan_pe_mdb: cli_malloc failed!\n");
        ret = CL_EMEM;
        goto end;
      }

      cl_hash_data("md5", hashme, exe_section->rsz, md5, ((void *)0));

      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MDB: "
                                "%u:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%"
                                "02x%02x%02x%02x%02x%02x\n",
                                exe_section->rsz, md5[0], md5[1], md5[2],
                                md5[3], md5[4], md5[5], md5[6], md5[7], md5[8],
                                md5[9], md5[10], md5[11], md5[12], md5[13],
                                md5[14], md5[15]);

      free(md5);

    } else {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MDB: %u:notgenerated\n", exe_section->rsz);
    }
  }

  for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
    if (foundsize[type] && cli_hm_scan(hashset[type], exe_section->rsz,
                                       &virname, mdb_sect, type) == CL_VIRUS) {
      ret = cli_append_virus(ctx, virname);
      if (ret != CL_CLEAN) {
        if (ret != CL_VIRUS)
          break;
        else if (!(ctx->options->general & 0x1))
          break;
      }
    }
    if (foundwild[type] &&
        cli_hm_scan_wild(hashset[type], &virname, mdb_sect, type) == CL_VIRUS) {
      ret = cli_append_virus(ctx, virname);
      if (ret != CL_CLEAN) {
        if (ret != CL_VIRUS)
          break;
        else if (!(ctx->options->general & 0x1))
          break;
      }
    }
  }

end:
  for (type = CLI_HASH_AVAIL_TYPES; type > 0;)
    free(hashset[--type]);
  return ret;
}

static char *pe_ordinal(const char *dll, uint16_t ord) {
  char name[64];
  name[0] = '\0';

  if (strncasecmp(dll, "WS2_32.dll", 10) == 0 ||
      strncasecmp(dll, "wsock32.dll", 11) == 0) {
    switch (ord) {
    case 1:
      sprintf(name, "accept");
      break;
    case 2:
      sprintf(name, "bind");
      break;
    case 3:
      sprintf(name, "closesocket");
      break;
    case 4:
      sprintf(name, "connect");
      break;
    case 5:
      sprintf(name, "getpeername");
      break;
    case 6:
      sprintf(name, "getsockname");
      break;
    case 7:
      sprintf(name, "getsockopt");
      break;
    case 8:
      sprintf(name, "htonl");
      break;
    case 9:
      sprintf(name, "htons");
      break;
    case 10:
      sprintf(name, "ioctlsocket");
      break;
    case 11:
      sprintf(name, "inet_addr");
      break;
    case 12:
      sprintf(name, "inet_ntoa");
      break;
    case 13:
      sprintf(name, "listen");
      break;
    case 14:
      sprintf(name, "ntohl");
      break;
    case 15:
      sprintf(name, "ntohs");
      break;
    case 16:
      sprintf(name, "recv");
      break;
    case 17:
      sprintf(name, "recvfrom");
      break;
    case 18:
      sprintf(name, "select");
      break;
    case 19:
      sprintf(name, "send");
      break;
    case 20:
      sprintf(name, "sendto");
      break;
    case 21:
      sprintf(name, "setsockopt");
      break;
    case 22:
      sprintf(name, "shutdown");
      break;
    case 23:
      sprintf(name, "socket");
      break;
    case 24:
      sprintf(name, "GetAddrInfoW");
      break;
    case 25:
      sprintf(name, "GetNameInfoW");
      break;
    case 26:
      sprintf(name, "WSApSetPostRoutine");
      break;
    case 27:
      sprintf(name, "FreeAddrInfoW");
      break;
    case 28:
      sprintf(name, "WPUCompleteOverlappedRequest");
      break;
    case 29:
      sprintf(name, "WSAAccept");
      break;
    case 30:
      sprintf(name, "WSAAddressToStringA");
      break;
    case 31:
      sprintf(name, "WSAAddressToStringW");
      break;
    case 32:
      sprintf(name, "WSACloseEvent");
      break;
    case 33:
      sprintf(name, "WSAConnect");
      break;
    case 34:
      sprintf(name, "WSACreateEvent");
      break;
    case 35:
      sprintf(name, "WSADuplicateSocketA");
      break;
    case 36:
      sprintf(name, "WSADuplicateSocketW");
      break;
    case 37:
      sprintf(name, "WSAEnumNameSpaceProvidersA");
      break;
    case 38:
      sprintf(name, "WSAEnumNameSpaceProvidersW");
      break;
    case 39:
      sprintf(name, "WSAEnumNetworkEvents");
      break;
    case 40:
      sprintf(name, "WSAEnumProtocolsA");
      break;
    case 41:
      sprintf(name, "WSAEnumProtocolsW");
      break;
    case 42:
      sprintf(name, "WSAEventSelect");
      break;
    case 43:
      sprintf(name, "WSAGetOverlappedResult");
      break;
    case 44:
      sprintf(name, "WSAGetQOSByName");
      break;
    case 45:
      sprintf(name, "WSAGetServiceClassInfoA");
      break;
    case 46:
      sprintf(name, "WSAGetServiceClassInfoW");
      break;
    case 47:
      sprintf(name, "WSAGetServiceClassNameByClassIdA");
      break;
    case 48:
      sprintf(name, "WSAGetServiceClassNameByClassIdW");
      break;
    case 49:
      sprintf(name, "WSAHtonl");
      break;
    case 50:
      sprintf(name, "WSAHtons");
      break;
    case 51:
      sprintf(name, "gethostbyaddr");
      break;
    case 52:
      sprintf(name, "gethostbyname");
      break;
    case 53:
      sprintf(name, "getprotobyname");
      break;
    case 54:
      sprintf(name, "getprotobynumber");
      break;
    case 55:
      sprintf(name, "getservbyname");
      break;
    case 56:
      sprintf(name, "getservbyport");
      break;
    case 57:
      sprintf(name, "gethostname");
      break;
    case 58:
      sprintf(name, "WSAInstallServiceClassA");
      break;
    case 59:
      sprintf(name, "WSAInstallServiceClassW");
      break;
    case 60:
      sprintf(name, "WSAIoctl");
      break;
    case 61:
      sprintf(name, "WSAJoinLeaf");
      break;
    case 62:
      sprintf(name, "WSALookupServiceBeginA");
      break;
    case 63:
      sprintf(name, "WSALookupServiceBeginW");
      break;
    case 64:
      sprintf(name, "WSALookupServiceEnd");
      break;
    case 65:
      sprintf(name, "WSALookupServiceNextA");
      break;
    case 66:
      sprintf(name, "WSALookupServiceNextW");
      break;
    case 67:
      sprintf(name, "WSANSPIoctl");
      break;
    case 68:
      sprintf(name, "WSANtohl");
      break;
    case 69:
      sprintf(name, "WSANtohs");
      break;
    case 70:
      sprintf(name, "WSAProviderConfigChange");
      break;
    case 71:
      sprintf(name, "WSARecv");
      break;
    case 72:
      sprintf(name, "WSARecvDisconnect");
      break;
    case 73:
      sprintf(name, "WSARecvFrom");
      break;
    case 74:
      sprintf(name, "WSARemoveServiceClass");
      break;
    case 75:
      sprintf(name, "WSAResetEvent");
      break;
    case 76:
      sprintf(name, "WSASend");
      break;
    case 77:
      sprintf(name, "WSASendDisconnect");
      break;
    case 78:
      sprintf(name, "WSASendTo");
      break;
    case 79:
      sprintf(name, "WSASetEvent");
      break;
    case 80:
      sprintf(name, "WSASetServiceA");
      break;
    case 81:
      sprintf(name, "WSASetServiceW");
      break;
    case 82:
      sprintf(name, "WSASocketA");
      break;
    case 83:
      sprintf(name, "WSASocketW");
      break;
    case 84:
      sprintf(name, "WSAStringToAddressA");
      break;
    case 85:
      sprintf(name, "WSAStringToAddressW");
      break;
    case 86:
      sprintf(name, "WSAWaitForMultipleEvents");
      break;
    case 87:
      sprintf(name, "WSCDeinstallProvider");
      break;
    case 88:
      sprintf(name, "WSCEnableNSProvider");
      break;
    case 89:
      sprintf(name, "WSCEnumProtocols");
      break;
    case 90:
      sprintf(name, "WSCGetProviderPath");
      break;
    case 91:
      sprintf(name, "WSCInstallNameSpace");
      break;
    case 92:
      sprintf(name, "WSCInstallProvider");
      break;
    case 93:
      sprintf(name, "WSCUnInstallNameSpace");
      break;
    case 94:
      sprintf(name, "WSCUpdateProvider");
      break;
    case 95:
      sprintf(name, "WSCWriteNameSpaceOrder");
      break;
    case 96:
      sprintf(name, "WSCWriteProviderOrder");
      break;
    case 97:
      sprintf(name, "freeaddrinfo");
      break;
    case 98:
      sprintf(name, "getaddrinfo");
      break;
    case 99:
      sprintf(name, "getnameinfo");
      break;
    case 101:
      sprintf(name, "WSAAsyncSelect");
      break;
    case 102:
      sprintf(name, "WSAAsyncGetHostByAddr");
      break;
    case 103:
      sprintf(name, "WSAAsyncGetHostByName");
      break;
    case 104:
      sprintf(name, "WSAAsyncGetProtoByNumber");
      break;
    case 105:
      sprintf(name, "WSAAsyncGetProtoByName");
      break;
    case 106:
      sprintf(name, "WSAAsyncGetServByPort");
      break;
    case 107:
      sprintf(name, "WSAAsyncGetServByName");
      break;
    case 108:
      sprintf(name, "WSACancelAsyncRequest");
      break;
    case 109:
      sprintf(name, "WSASetBlockingHook");
      break;
    case 110:
      sprintf(name, "WSAUnhookBlockingHook");
      break;
    case 111:
      sprintf(name, "WSAGetLastError");
      break;
    case 112:
      sprintf(name, "WSASetLastError");
      break;
    case 113:
      sprintf(name, "WSACancelBlockingCall");
      break;
    case 114:
      sprintf(name, "WSAIsBlocking");
      break;
    case 115:
      sprintf(name, "WSAStartup");
      break;
    case 116:
      sprintf(name, "WSACleanup");
      break;
    case 151:
      sprintf(name, "__WSAFDIsSet");
      break;
    case 500:
      sprintf(name, "WEP");
      break;
    default:
      break;
    }
  } else if (strncasecmp(dll, "oleaut32.dll", 12) == 0) {
    switch (ord) {
    case 2:
      sprintf(name, "SysAllocString");
      break;
    case 3:
      sprintf(name, "SysReAllocString");
      break;
    case 4:
      sprintf(name, "SysAllocStringLen");
      break;
    case 5:
      sprintf(name, "SysReAllocStringLen");
      break;
    case 6:
      sprintf(name, "SysFreeString");
      break;
    case 7:
      sprintf(name, "SysStringLen");
      break;
    case 8:
      sprintf(name, "VariantInit");
      break;
    case 9:
      sprintf(name, "VariantClear");
      break;
    case 10:
      sprintf(name, "VariantCopy");
      break;
    case 11:
      sprintf(name, "VariantCopyInd");
      break;
    case 12:
      sprintf(name, "VariantChangeType");
      break;
    case 13:
      sprintf(name, "VariantTimeToDosDateTime");
      break;
    case 14:
      sprintf(name, "DosDateTimeToVariantTime");
      break;
    case 15:
      sprintf(name, "SafeArrayCreate");
      break;
    case 16:
      sprintf(name, "SafeArrayDestroy");
      break;
    case 17:
      sprintf(name, "SafeArrayGetDim");
      break;
    case 18:
      sprintf(name, "SafeArrayGetElemsize");
      break;
    case 19:
      sprintf(name, "SafeArrayGetUBound");
      break;
    case 20:
      sprintf(name, "SafeArrayGetLBound");
      break;
    case 21:
      sprintf(name, "SafeArrayLock");
      break;
    case 22:
      sprintf(name, "SafeArrayUnlock");
      break;
    case 23:
      sprintf(name, "SafeArrayAccessData");
      break;
    case 24:
      sprintf(name, "SafeArrayUnaccessData");
      break;
    case 25:
      sprintf(name, "SafeArrayGetElement");
      break;
    case 26:
      sprintf(name, "SafeArrayPutElement");
      break;
    case 27:
      sprintf(name, "SafeArrayCopy");
      break;
    case 28:
      sprintf(name, "DispGetParam");
      break;
    case 29:
      sprintf(name, "DispGetIDsOfNames");
      break;
    case 30:
      sprintf(name, "DispInvoke");
      break;
    case 31:
      sprintf(name, "CreateDispTypeInfo");
      break;
    case 32:
      sprintf(name, "CreateStdDispatch");
      break;
    case 33:
      sprintf(name, "RegisterActiveObject");
      break;
    case 34:
      sprintf(name, "RevokeActiveObject");
      break;
    case 35:
      sprintf(name, "GetActiveObject");
      break;
    case 36:
      sprintf(name, "SafeArrayAllocDescriptor");
      break;
    case 37:
      sprintf(name, "SafeArrayAllocData");
      break;
    case 38:
      sprintf(name, "SafeArrayDestroyDescriptor");
      break;
    case 39:
      sprintf(name, "SafeArrayDestroyData");
      break;
    case 40:
      sprintf(name, "SafeArrayRedim");
      break;
    case 41:
      sprintf(name, "SafeArrayAllocDescriptorEx");
      break;
    case 42:
      sprintf(name, "SafeArrayCreateEx");
      break;
    case 43:
      sprintf(name, "SafeArrayCreateVectorEx");
      break;
    case 44:
      sprintf(name, "SafeArraySetRecordInfo");
      break;
    case 45:
      sprintf(name, "SafeArrayGetRecordInfo");
      break;
    case 46:
      sprintf(name, "VarParseNumFromStr");
      break;
    case 47:
      sprintf(name, "VarNumFromParseNum");
      break;
    case 48:
      sprintf(name, "VarI2FromUI1");
      break;
    case 49:
      sprintf(name, "VarI2FromI4");
      break;
    case 50:
      sprintf(name, "VarI2FromR4");
      break;
    case 51:
      sprintf(name, "VarI2FromR8");
      break;
    case 52:
      sprintf(name, "VarI2FromCy");
      break;
    case 53:
      sprintf(name, "VarI2FromDate");
      break;
    case 54:
      sprintf(name, "VarI2FromStr");
      break;
    case 55:
      sprintf(name, "VarI2FromDisp");
      break;
    case 56:
      sprintf(name, "VarI2FromBool");
      break;
    case 57:
      sprintf(name, "SafeArraySetIID");
      break;
    case 58:
      sprintf(name, "VarI4FromUI1");
      break;
    case 59:
      sprintf(name, "VarI4FromI2");
      break;
    case 60:
      sprintf(name, "VarI4FromR4");
      break;
    case 61:
      sprintf(name, "VarI4FromR8");
      break;
    case 62:
      sprintf(name, "VarI4FromCy");
      break;
    case 63:
      sprintf(name, "VarI4FromDate");
      break;
    case 64:
      sprintf(name, "VarI4FromStr");
      break;
    case 65:
      sprintf(name, "VarI4FromDisp");
      break;
    case 66:
      sprintf(name, "VarI4FromBool");
      break;
    case 67:
      sprintf(name, "SafeArrayGetIID");
      break;
    case 68:
      sprintf(name, "VarR4FromUI1");
      break;
    case 69:
      sprintf(name, "VarR4FromI2");
      break;
    case 70:
      sprintf(name, "VarR4FromI4");
      break;
    case 71:
      sprintf(name, "VarR4FromR8");
      break;
    case 72:
      sprintf(name, "VarR4FromCy");
      break;
    case 73:
      sprintf(name, "VarR4FromDate");
      break;
    case 74:
      sprintf(name, "VarR4FromStr");
      break;
    case 75:
      sprintf(name, "VarR4FromDisp");
      break;
    case 76:
      sprintf(name, "VarR4FromBool");
      break;
    case 77:
      sprintf(name, "SafeArrayGetVartype");
      break;
    case 78:
      sprintf(name, "VarR8FromUI1");
      break;
    case 79:
      sprintf(name, "VarR8FromI2");
      break;
    case 80:
      sprintf(name, "VarR8FromI4");
      break;
    case 81:
      sprintf(name, "VarR8FromR4");
      break;
    case 82:
      sprintf(name, "VarR8FromCy");
      break;
    case 83:
      sprintf(name, "VarR8FromDate");
      break;
    case 84:
      sprintf(name, "VarR8FromStr");
      break;
    case 85:
      sprintf(name, "VarR8FromDisp");
      break;
    case 86:
      sprintf(name, "VarR8FromBool");
      break;
    case 87:
      sprintf(name, "VarFormat");
      break;
    case 88:
      sprintf(name, "VarDateFromUI1");
      break;
    case 89:
      sprintf(name, "VarDateFromI2");
      break;
    case 90:
      sprintf(name, "VarDateFromI4");
      break;
    case 91:
      sprintf(name, "VarDateFromR4");
      break;
    case 92:
      sprintf(name, "VarDateFromR8");
      break;
    case 93:
      sprintf(name, "VarDateFromCy");
      break;
    case 94:
      sprintf(name, "VarDateFromStr");
      break;
    case 95:
      sprintf(name, "VarDateFromDisp");
      break;
    case 96:
      sprintf(name, "VarDateFromBool");
      break;
    case 97:
      sprintf(name, "VarFormatDateTime");
      break;
    case 98:
      sprintf(name, "VarCyFromUI1");
      break;
    case 99:
      sprintf(name, "VarCyFromI2");
      break;
    case 100:
      sprintf(name, "VarCyFromI4");
      break;
    case 101:
      sprintf(name, "VarCyFromR4");
      break;
    case 102:
      sprintf(name, "VarCyFromR8");
      break;
    case 103:
      sprintf(name, "VarCyFromDate");
      break;
    case 104:
      sprintf(name, "VarCyFromStr");
      break;
    case 105:
      sprintf(name, "VarCyFromDisp");
      break;
    case 106:
      sprintf(name, "VarCyFromBool");
      break;
    case 107:
      sprintf(name, "VarFormatNumber");
      break;
    case 108:
      sprintf(name, "VarBstrFromUI1");
      break;
    case 109:
      sprintf(name, "VarBstrFromI2");
      break;
    case 110:
      sprintf(name, "VarBstrFromI4");
      break;
    case 111:
      sprintf(name, "VarBstrFromR4");
      break;
    case 112:
      sprintf(name, "VarBstrFromR8");
      break;
    case 113:
      sprintf(name, "VarBstrFromCy");
      break;
    case 114:
      sprintf(name, "VarBstrFromDate");
      break;
    case 115:
      sprintf(name, "VarBstrFromDisp");
      break;
    case 116:
      sprintf(name, "VarBstrFromBool");
      break;
    case 117:
      sprintf(name, "VarFormatPercent");
      break;
    case 118:
      sprintf(name, "VarBoolFromUI1");
      break;
    case 119:
      sprintf(name, "VarBoolFromI2");
      break;
    case 120:
      sprintf(name, "VarBoolFromI4");
      break;
    case 121:
      sprintf(name, "VarBoolFromR4");
      break;
    case 122:
      sprintf(name, "VarBoolFromR8");
      break;
    case 123:
      sprintf(name, "VarBoolFromDate");
      break;
    case 124:
      sprintf(name, "VarBoolFromCy");
      break;
    case 125:
      sprintf(name, "VarBoolFromStr");
      break;
    case 126:
      sprintf(name, "VarBoolFromDisp");
      break;
    case 127:
      sprintf(name, "VarFormatCurrency");
      break;
    case 128:
      sprintf(name, "VarWeekdayName");
      break;
    case 129:
      sprintf(name, "VarMonthName");
      break;
    case 130:
      sprintf(name, "VarUI1FromI2");
      break;
    case 131:
      sprintf(name, "VarUI1FromI4");
      break;
    case 132:
      sprintf(name, "VarUI1FromR4");
      break;
    case 133:
      sprintf(name, "VarUI1FromR8");
      break;
    case 134:
      sprintf(name, "VarUI1FromCy");
      break;
    case 135:
      sprintf(name, "VarUI1FromDate");
      break;
    case 136:
      sprintf(name, "VarUI1FromStr");
      break;
    case 137:
      sprintf(name, "VarUI1FromDisp");
      break;
    case 138:
      sprintf(name, "VarUI1FromBool");
      break;
    case 139:
      sprintf(name, "VarFormatFromTokens");
      break;
    case 140:
      sprintf(name, "VarTokenizeFormatString");
      break;
    case 141:
      sprintf(name, "VarAdd");
      break;
    case 142:
      sprintf(name, "VarAnd");
      break;
    case 143:
      sprintf(name, "VarDiv");
      break;
    case 144:
      sprintf(name, "DllCanUnloadNow");
      break;
    case 145:
      sprintf(name, "DllGetClassObject");
      break;
    case 146:
      sprintf(name, "DispCallFunc");
      break;
    case 147:
      sprintf(name, "VariantChangeTypeEx");
      break;
    case 148:
      sprintf(name, "SafeArrayPtrOfIndex");
      break;
    case 149:
      sprintf(name, "SysStringByteLen");
      break;
    case 150:
      sprintf(name, "SysAllocStringByteLen");
      break;
    case 151:
      sprintf(name, "DllRegisterServer");
      break;
    case 152:
      sprintf(name, "VarEqv");
      break;
    case 153:
      sprintf(name, "VarIdiv");
      break;
    case 154:
      sprintf(name, "VarImp");
      break;
    case 155:
      sprintf(name, "VarMod");
      break;
    case 156:
      sprintf(name, "VarMul");
      break;
    case 157:
      sprintf(name, "VarOr");
      break;
    case 158:
      sprintf(name, "VarPow");
      break;
    case 159:
      sprintf(name, "VarSub");
      break;
    case 160:
      sprintf(name, "CreateTypeLib");
      break;
    case 161:
      sprintf(name, "LoadTypeLib");
      break;
    case 162:
      sprintf(name, "LoadRegTypeLib");
      break;
    case 163:
      sprintf(name, "RegisterTypeLib");
      break;
    case 164:
      sprintf(name, "QueryPathOfRegTypeLib");
      break;
    case 165:
      sprintf(name, "LHashValOfNameSys");
      break;
    case 166:
      sprintf(name, "LHashValOfNameSysA");
      break;
    case 167:
      sprintf(name, "VarXor");
      break;
    case 168:
      sprintf(name, "VarAbs");
      break;
    case 169:
      sprintf(name, "VarFix");
      break;
    case 170:
      sprintf(name, "OaBuildVersion");
      break;
    case 171:
      sprintf(name, "ClearCustData");
      break;
    case 172:
      sprintf(name, "VarInt");
      break;
    case 173:
      sprintf(name, "VarNeg");
      break;
    case 174:
      sprintf(name, "VarNot");
      break;
    case 175:
      sprintf(name, "VarRound");
      break;
    case 176:
      sprintf(name, "VarCmp");
      break;
    case 177:
      sprintf(name, "VarDecAdd");
      break;
    case 178:
      sprintf(name, "VarDecDiv");
      break;
    case 179:
      sprintf(name, "VarDecMul");
      break;
    case 180:
      sprintf(name, "CreateTypeLib2");
      break;
    case 181:
      sprintf(name, "VarDecSub");
      break;
    case 182:
      sprintf(name, "VarDecAbs");
      break;
    case 183:
      sprintf(name, "LoadTypeLibEx");
      break;
    case 184:
      sprintf(name, "SystemTimeToVariantTime");
      break;
    case 185:
      sprintf(name, "VariantTimeToSystemTime");
      break;
    case 186:
      sprintf(name, "UnRegisterTypeLib");
      break;
    case 187:
      sprintf(name, "VarDecFix");
      break;
    case 188:
      sprintf(name, "VarDecInt");
      break;
    case 189:
      sprintf(name, "VarDecNeg");
      break;
    case 190:
      sprintf(name, "VarDecFromUI1");
      break;
    case 191:
      sprintf(name, "VarDecFromI2");
      break;
    case 192:
      sprintf(name, "VarDecFromI4");
      break;
    case 193:
      sprintf(name, "VarDecFromR4");
      break;
    case 194:
      sprintf(name, "VarDecFromR8");
      break;
    case 195:
      sprintf(name, "VarDecFromDate");
      break;
    case 196:
      sprintf(name, "VarDecFromCy");
      break;
    case 197:
      sprintf(name, "VarDecFromStr");
      break;
    case 198:
      sprintf(name, "VarDecFromDisp");
      break;
    case 199:
      sprintf(name, "VarDecFromBool");
      break;
    case 200:
      sprintf(name, "GetErrorInfo");
      break;
    case 201:
      sprintf(name, "SetErrorInfo");
      break;
    case 202:
      sprintf(name, "CreateErrorInfo");
      break;
    case 203:
      sprintf(name, "VarDecRound");
      break;
    case 204:
      sprintf(name, "VarDecCmp");
      break;
    case 205:
      sprintf(name, "VarI2FromI1");
      break;
    case 206:
      sprintf(name, "VarI2FromUI2");
      break;
    case 207:
      sprintf(name, "VarI2FromUI4");
      break;
    case 208:
      sprintf(name, "VarI2FromDec");
      break;
    case 209:
      sprintf(name, "VarI4FromI1");
      break;
    case 210:
      sprintf(name, "VarI4FromUI2");
      break;
    case 211:
      sprintf(name, "VarI4FromUI4");
      break;
    case 212:
      sprintf(name, "VarI4FromDec");
      break;
    case 213:
      sprintf(name, "VarR4FromI1");
      break;
    case 214:
      sprintf(name, "VarR4FromUI2");
      break;
    case 215:
      sprintf(name, "VarR4FromUI4");
      break;
    case 216:
      sprintf(name, "VarR4FromDec");
      break;
    case 217:
      sprintf(name, "VarR8FromI1");
      break;
    case 218:
      sprintf(name, "VarR8FromUI2");
      break;
    case 219:
      sprintf(name, "VarR8FromUI4");
      break;
    case 220:
      sprintf(name, "VarR8FromDec");
      break;
    case 221:
      sprintf(name, "VarDateFromI1");
      break;
    case 222:
      sprintf(name, "VarDateFromUI2");
      break;
    case 223:
      sprintf(name, "VarDateFromUI4");
      break;
    case 224:
      sprintf(name, "VarDateFromDec");
      break;
    case 225:
      sprintf(name, "VarCyFromI1");
      break;
    case 226:
      sprintf(name, "VarCyFromUI2");
      break;
    case 227:
      sprintf(name, "VarCyFromUI4");
      break;
    case 228:
      sprintf(name, "VarCyFromDec");
      break;
    case 229:
      sprintf(name, "VarBstrFromI1");
      break;
    case 230:
      sprintf(name, "VarBstrFromUI2");
      break;
    case 231:
      sprintf(name, "VarBstrFromUI4");
      break;
    case 232:
      sprintf(name, "VarBstrFromDec");
      break;
    case 233:
      sprintf(name, "VarBoolFromI1");
      break;
    case 234:
      sprintf(name, "VarBoolFromUI2");
      break;
    case 235:
      sprintf(name, "VarBoolFromUI4");
      break;
    case 236:
      sprintf(name, "VarBoolFromDec");
      break;
    case 237:
      sprintf(name, "VarUI1FromI1");
      break;
    case 238:
      sprintf(name, "VarUI1FromUI2");
      break;
    case 239:
      sprintf(name, "VarUI1FromUI4");
      break;
    case 240:
      sprintf(name, "VarUI1FromDec");
      break;
    case 241:
      sprintf(name, "VarDecFromI1");
      break;
    case 242:
      sprintf(name, "VarDecFromUI2");
      break;
    case 243:
      sprintf(name, "VarDecFromUI4");
      break;
    case 244:
      sprintf(name, "VarI1FromUI1");
      break;
    case 245:
      sprintf(name, "VarI1FromI2");
      break;
    case 246:
      sprintf(name, "VarI1FromI4");
      break;
    case 247:
      sprintf(name, "VarI1FromR4");
      break;
    case 248:
      sprintf(name, "VarI1FromR8");
      break;
    case 249:
      sprintf(name, "VarI1FromDate");
      break;
    case 250:
      sprintf(name, "VarI1FromCy");
      break;
    case 251:
      sprintf(name, "VarI1FromStr");
      break;
    case 252:
      sprintf(name, "VarI1FromDisp");
      break;
    case 253:
      sprintf(name, "VarI1FromBool");
      break;
    case 254:
      sprintf(name, "VarI1FromUI2");
      break;
    case 255:
      sprintf(name, "VarI1FromUI4");
      break;
    case 256:
      sprintf(name, "VarI1FromDec");
      break;
    case 257:
      sprintf(name, "VarUI2FromUI1");
      break;
    case 258:
      sprintf(name, "VarUI2FromI2");
      break;
    case 259:
      sprintf(name, "VarUI2FromI4");
      break;
    case 260:
      sprintf(name, "VarUI2FromR4");
      break;
    case 261:
      sprintf(name, "VarUI2FromR8");
      break;
    case 262:
      sprintf(name, "VarUI2FromDate");
      break;
    case 263:
      sprintf(name, "VarUI2FromCy");
      break;
    case 264:
      sprintf(name, "VarUI2FromStr");
      break;
    case 265:
      sprintf(name, "VarUI2FromDisp");
      break;
    case 266:
      sprintf(name, "VarUI2FromBool");
      break;
    case 267:
      sprintf(name, "VarUI2FromI1");
      break;
    case 268:
      sprintf(name, "VarUI2FromUI4");
      break;
    case 269:
      sprintf(name, "VarUI2FromDec");
      break;
    case 270:
      sprintf(name, "VarUI4FromUI1");
      break;
    case 271:
      sprintf(name, "VarUI4FromI2");
      break;
    case 272:
      sprintf(name, "VarUI4FromI4");
      break;
    case 273:
      sprintf(name, "VarUI4FromR4");
      break;
    case 274:
      sprintf(name, "VarUI4FromR8");
      break;
    case 275:
      sprintf(name, "VarUI4FromDate");
      break;
    case 276:
      sprintf(name, "VarUI4FromCy");
      break;
    case 277:
      sprintf(name, "VarUI4FromStr");
      break;
    case 278:
      sprintf(name, "VarUI4FromDisp");
      break;
    case 279:
      sprintf(name, "VarUI4FromBool");
      break;
    case 280:
      sprintf(name, "VarUI4FromI1");
      break;
    case 281:
      sprintf(name, "VarUI4FromUI2");
      break;
    case 282:
      sprintf(name, "VarUI4FromDec");
      break;
    case 283:
      sprintf(name, "BSTR_UserSize");
      break;
    case 284:
      sprintf(name, "BSTR_UserMarshal");
      break;
    case 285:
      sprintf(name, "BSTR_UserUnmarshal");
      break;
    case 286:
      sprintf(name, "BSTR_UserFree");
      break;
    case 287:
      sprintf(name, "VARIANT_UserSize");
      break;
    case 288:
      sprintf(name, "VARIANT_UserMarshal");
      break;
    case 289:
      sprintf(name, "VARIANT_UserUnmarshal");
      break;
    case 290:
      sprintf(name, "VARIANT_UserFree");
      break;
    case 291:
      sprintf(name, "LPSAFEARRAY_UserSize");
      break;
    case 292:
      sprintf(name, "LPSAFEARRAY_UserMarshal");
      break;
    case 293:
      sprintf(name, "LPSAFEARRAY_UserUnmarshal");
      break;
    case 294:
      sprintf(name, "LPSAFEARRAY_UserFree");
      break;
    case 295:
      sprintf(name, "LPSAFEARRAY_Size");
      break;
    case 296:
      sprintf(name, "LPSAFEARRAY_Marshal");
      break;
    case 297:
      sprintf(name, "LPSAFEARRAY_Unmarshal");
      break;
    case 298:
      sprintf(name, "VarDecCmpR8");
      break;
    case 299:
      sprintf(name, "VarCyAdd");
      break;
    case 300:
      sprintf(name, "DllUnregisterServer");
      break;
    case 301:
      sprintf(name, "OACreateTypeLib2");
      break;
    case 303:
      sprintf(name, "VarCyMul");
      break;
    case 304:
      sprintf(name, "VarCyMulI4");
      break;
    case 305:
      sprintf(name, "VarCySub");
      break;
    case 306:
      sprintf(name, "VarCyAbs");
      break;
    case 307:
      sprintf(name, "VarCyFix");
      break;
    case 308:
      sprintf(name, "VarCyInt");
      break;
    case 309:
      sprintf(name, "VarCyNeg");
      break;
    case 310:
      sprintf(name, "VarCyRound");
      break;
    case 311:
      sprintf(name, "VarCyCmp");
      break;
    case 312:
      sprintf(name, "VarCyCmpR8");
      break;
    case 313:
      sprintf(name, "VarBstrCat");
      break;
    case 314:
      sprintf(name, "VarBstrCmp");
      break;
    case 315:
      sprintf(name, "VarR8Pow");
      break;
    case 316:
      sprintf(name, "VarR4CmpR8");
      break;
    case 317:
      sprintf(name, "VarR8Round");
      break;
    case 318:
      sprintf(name, "VarCat");
      break;
    case 319:
      sprintf(name, "VarDateFromUdateEx");
      break;
    case 322:
      sprintf(name, "GetRecordInfoFromGuids");
      break;
    case 323:
      sprintf(name, "GetRecordInfoFromTypeInfo");
      break;
    case 325:
      sprintf(name, "SetVarConversionLocaleSetting");
      break;
    case 326:
      sprintf(name, "GetVarConversionLocaleSetting");
      break;
    case 327:
      sprintf(name, "SetOaNoCache");
      break;
    case 329:
      sprintf(name, "VarCyMulI8");
      break;
    case 330:
      sprintf(name, "VarDateFromUdate");
      break;
    case 331:
      sprintf(name, "VarUdateFromDate");
      break;
    case 332:
      sprintf(name, "GetAltMonthNames");
      break;
    case 333:
      sprintf(name, "VarI8FromUI1");
      break;
    case 334:
      sprintf(name, "VarI8FromI2");
      break;
    case 335:
      sprintf(name, "VarI8FromR4");
      break;
    case 336:
      sprintf(name, "VarI8FromR8");
      break;
    case 337:
      sprintf(name, "VarI8FromCy");
      break;
    case 338:
      sprintf(name, "VarI8FromDate");
      break;
    case 339:
      sprintf(name, "VarI8FromStr");
      break;
    case 340:
      sprintf(name, "VarI8FromDisp");
      break;
    case 341:
      sprintf(name, "VarI8FromBool");
      break;
    case 342:
      sprintf(name, "VarI8FromI1");
      break;
    case 343:
      sprintf(name, "VarI8FromUI2");
      break;
    case 344:
      sprintf(name, "VarI8FromUI4");
      break;
    case 345:
      sprintf(name, "VarI8FromDec");
      break;
    case 346:
      sprintf(name, "VarI2FromI8");
      break;
    case 347:
      sprintf(name, "VarI2FromUI8");
      break;
    case 348:
      sprintf(name, "VarI4FromI8");
      break;
    case 349:
      sprintf(name, "VarI4FromUI8");
      break;
    case 360:
      sprintf(name, "VarR4FromI8");
      break;
    case 361:
      sprintf(name, "VarR4FromUI8");
      break;
    case 362:
      sprintf(name, "VarR8FromI8");
      break;
    case 363:
      sprintf(name, "VarR8FromUI8");
      break;
    case 364:
      sprintf(name, "VarDateFromI8");
      break;
    case 365:
      sprintf(name, "VarDateFromUI8");
      break;
    case 366:
      sprintf(name, "VarCyFromI8");
      break;
    case 367:
      sprintf(name, "VarCyFromUI8");
      break;
    case 368:
      sprintf(name, "VarBstrFromI8");
      break;
    case 369:
      sprintf(name, "VarBstrFromUI8");
      break;
    case 370:
      sprintf(name, "VarBoolFromI8");
      break;
    case 371:
      sprintf(name, "VarBoolFromUI8");
      break;
    case 372:
      sprintf(name, "VarUI1FromI8");
      break;
    case 373:
      sprintf(name, "VarUI1FromUI8");
      break;
    case 374:
      sprintf(name, "VarDecFromI8");
      break;
    case 375:
      sprintf(name, "VarDecFromUI8");
      break;
    case 376:
      sprintf(name, "VarI1FromI8");
      break;
    case 377:
      sprintf(name, "VarI1FromUI8");
      break;
    case 378:
      sprintf(name, "VarUI2FromI8");
      break;
    case 379:
      sprintf(name, "VarUI2FromUI8");
      break;
    case 401:
      sprintf(name, "OleLoadPictureEx");
      break;
    case 402:
      sprintf(name, "OleLoadPictureFileEx");
      break;
    case 411:
      sprintf(name, "SafeArrayCreateVector");
      break;
    case 412:
      sprintf(name, "SafeArrayCopyData");
      break;
    case 413:
      sprintf(name, "VectorFromBstr");
      break;
    case 414:
      sprintf(name, "BstrFromVector");
      break;
    case 415:
      sprintf(name, "OleIconToCursor");
      break;
    case 416:
      sprintf(name, "OleCreatePropertyFrameIndirect");
      break;
    case 417:
      sprintf(name, "OleCreatePropertyFrame");
      break;
    case 418:
      sprintf(name, "OleLoadPicture");
      break;
    case 419:
      sprintf(name, "OleCreatePictureIndirect");
      break;
    case 420:
      sprintf(name, "OleCreateFontIndirect");
      break;
    case 421:
      sprintf(name, "OleTranslateColor");
      break;
    case 422:
      sprintf(name, "OleLoadPictureFile");
      break;
    case 423:
      sprintf(name, "OleSavePictureFile");
      break;
    case 424:
      sprintf(name, "OleLoadPicturePath");
      break;
    case 425:
      sprintf(name, "VarUI4FromI8");
      break;
    case 426:
      sprintf(name, "VarUI4FromUI8");
      break;
    case 427:
      sprintf(name, "VarI8FromUI8");
      break;
    case 428:
      sprintf(name, "VarUI8FromI8");
      break;
    case 429:
      sprintf(name, "VarUI8FromUI1");
      break;
    case 430:
      sprintf(name, "VarUI8FromI2");
      break;
    case 431:
      sprintf(name, "VarUI8FromR4");
      break;
    case 432:
      sprintf(name, "VarUI8FromR8");
      break;
    case 433:
      sprintf(name, "VarUI8FromCy");
      break;
    case 434:
      sprintf(name, "VarUI8FromDate");
      break;
    case 435:
      sprintf(name, "VarUI8FromStr");
      break;
    case 436:
      sprintf(name, "VarUI8FromDisp");
      break;
    case 437:
      sprintf(name, "VarUI8FromBool");
      break;
    case 438:
      sprintf(name, "VarUI8FromI1");
      break;
    case 439:
      sprintf(name, "VarUI8FromUI2");
      break;
    case 440:
      sprintf(name, "VarUI8FromUI4");
      break;
    case 441:
      sprintf(name, "VarUI8FromDec");
      break;
    case 442:
      sprintf(name, "RegisterTypeLibForUser");
      break;
    case 443:
      sprintf(name, "UnRegisterTypeLibForUser");
      break;
    default:
      break;
    }
  }

  if (name[0] == '\0')
    sprintf(name, "ord%u", ord);

  return cli_strdup(name);
}

static int validate_impname(const char *name, uint32_t length, int dll) {
  uint32_t i = 0;
  const char *c = name;

  if (!name || length == 0)
    return 1;

  while (i < length && *c != '\0') {
    if ((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'z') ||
        (*c >= 'A' && *c <= 'Z') || (*c == '_') || (dll && *c == '.')) {

      c++;
      i++;
    } else
      return 0;
  }

  return 1;
}

static inline int hash_impfns(cli_ctx *ctx, void **hashctx, uint32_t *impsz,
                              struct pe_image_import_descriptor *image,
                              const char *dllname, struct cli_exe_info *peinfo,
                              int *first) {
  uint32_t thuoff = 0, offset;
  fmap_t *map = *ctx->fmap;
  size_t dlllen = 0, fsize = map->len;
  unsigned int err = 0;
  int num_fns = 0, ret = CL_SUCCESS;
  const char *buffer;
  enum CLI_HASH_TYPE type;

  void *imptbl = ((void *)0);

  if (image->u.OriginalFirstThunk)
    thuoff = cli_rawaddr(image->u.OriginalFirstThunk, peinfo->sections,
                         peinfo->nsections, &err, fsize, peinfo->hdr_size);
  if (err || thuoff == 0)
    thuoff = cli_rawaddr(image->FirstThunk, peinfo->sections, peinfo->nsections,
                         &err, fsize, peinfo->hdr_size);
  if (err) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("scan_pe: invalid rva for image first thunk\n");
    return CL_EFORMAT;
  }
  if (!peinfo->is_pe32plus) {
    struct pe_image_thunk32 thunk32;

    while (
        (num_fns < 1024) &&
        (fmap_readn(map, &thunk32, thuoff, sizeof(struct pe_image_thunk32)) ==
         sizeof(struct pe_image_thunk32)) &&
        (thunk32.u.Ordinal != 0)) {
      char *funcname = ((void *)0);
      thuoff += sizeof(struct pe_image_thunk32);

      thunk32.u.Ordinal = ((uint32_t)(
          ((const union unaligned_32 *)(&(thunk32.u.Ordinal)))->una_s32));

      if (!(thunk32.u.Ordinal & 0x80000000)) {
        offset = cli_rawaddr(thunk32.u.Function, peinfo->sections,
                             peinfo->nsections, &err, fsize, peinfo->hdr_size);

        if (!ret) {

          if ((buffer = fmap_need_off_once(
                   map, offset + sizeof(uint16_t),
                   ((256) < (fsize - offset) ? (256) : (fsize - offset)))) !=
              ((void *)0)) {
            funcname = strndup(
                buffer, ((256) < (fsize - offset) ? (256) : (fsize - offset)));
            if (funcname == ((void *)0)) {
              (!__builtin_expect(!!(cli_debug_flag), 0))
                  ? (void)0
                  : cli_dbgmsg_internal(
                        "scan_pe: cannot duplicate function name\n");
              return CL_EMEM;
            }
          }
        }
      } else {

        funcname = pe_ordinal(dllname, thunk32.u.Ordinal & 0xFFFF);
        if (funcname == ((void *)0)) {
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal(
                    "scan_pe: cannot duplicate function name\n");
          return CL_EMEM;
        }
      }

      do {
        if (funcname) {
          size_t i, j;
          char *fname;
          size_t funclen;
          if (dlllen == 0) {
            char *ext = strstr(dllname, ".");
            if (ext && (strncasecmp(ext, ".ocx", 4) == 0 ||
                        strncasecmp(ext, ".sys", 4) == 0 ||
                        strncasecmp(ext, ".dll", 4) == 0))
              dlllen = ext - dllname;
            else
              dlllen = strlen(dllname);
          }
          funclen = strlen(funcname);
          if (validate_impname(funcname, funclen, 1) == 0) {
            (!__builtin_expect(!!(cli_debug_flag), 0))
                ? (void)0
                : cli_dbgmsg_internal(
                      "scan_pe: invalid name for imported function\n");
            ret = CL_EFORMAT;
            break;
          }
          fname = cli_calloc(funclen + dlllen + 3, sizeof(char));
          if (fname == ((void *)0)) {
            (!__builtin_expect(!!(cli_debug_flag), 0))
                ? (void)0
                : cli_dbgmsg_internal(
                      "scan_pe: cannot allocate memory for imphash string\n");
            ret = CL_EMEM;
            break;
          }
          j = 0;
          if (!*first)
            fname[j++] = ',';
          for (i = 0; i < dlllen; i++, j++)
            fname[j] = tolower(dllname[i]);
          fname[j++] = '.';
          for (i = 0; i < funclen; i++, j++)
            fname[j] = tolower(funcname[i]);
          if (imptbl) {
            char *jname = *first ? fname : fname + 1;
            cli_jsonstr_nojson(((void *)0), jname);
          }
          for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
            cl_update_hash(hashctx[type], fname, strlen(fname));
          *impsz += strlen(fname);
          *first = 0;
          free(fname);
        }
      } while (0);
      free(funcname);
      if (ret != CL_SUCCESS)
        return ret;
    }
  } else {
    struct pe_image_thunk64 thunk64;

    while (
        (num_fns < 1024) &&
        (fmap_readn(map, &thunk64, thuoff, sizeof(struct pe_image_thunk64)) ==
         sizeof(struct pe_image_thunk64)) &&
        (thunk64.u.Ordinal != 0)) {
      char *funcname = ((void *)0);
      thuoff += sizeof(struct pe_image_thunk64);

      thunk64.u.Ordinal = ((uint64_t)(
          ((const union unaligned_64 *)(&(thunk64.u.Ordinal)))->una_s64));

      if (!(thunk64.u.Ordinal & 0x8000000000000000L)) {
        offset = cli_rawaddr(thunk64.u.Function, peinfo->sections,
                             peinfo->nsections, &err, fsize, peinfo->hdr_size);

        if (!err) {

          if ((buffer = fmap_need_off_once(
                   map, offset + sizeof(uint16_t),
                   ((256) < (fsize - offset) ? (256) : (fsize - offset)))) !=
              ((void *)0)) {
            funcname = strndup(
                buffer, ((256) < (fsize - offset) ? (256) : (fsize - offset)));
            if (funcname == ((void *)0)) {
              (!__builtin_expect(!!(cli_debug_flag), 0))
                  ? (void)0
                  : cli_dbgmsg_internal(
                        "scan_pe: cannot duplicate function name\n");
              return CL_EMEM;
            }
          }
        }
      } else {

        funcname = pe_ordinal(dllname, thunk64.u.Ordinal & 0xFFFF);
        if (funcname == ((void *)0)) {
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal(
                    "scan_pe: cannot duplicate function name\n");
          return CL_EMEM;
        }
      }

      do {
        if (funcname) {
          size_t i, j;
          char *fname;
          size_t funclen;
          if (dlllen == 0) {
            char *ext = strstr(dllname, ".");
            if (ext && (strncasecmp(ext, ".ocx", 4) == 0 ||
                        strncasecmp(ext, ".sys", 4) == 0 ||
                        strncasecmp(ext, ".dll", 4) == 0))
              dlllen = ext - dllname;
            else
              dlllen = strlen(dllname);
          }
          funclen = strlen(funcname);
          if (validate_impname(funcname, funclen, 1) == 0) {
            (!__builtin_expect(!!(cli_debug_flag), 0))
                ? (void)0
                : cli_dbgmsg_internal(
                      "scan_pe: invalid name for imported function\n");
            ret = CL_EFORMAT;
            break;
          }
          fname = cli_calloc(funclen + dlllen + 3, sizeof(char));
          if (fname == ((void *)0)) {
            (!__builtin_expect(!!(cli_debug_flag), 0))
                ? (void)0
                : cli_dbgmsg_internal(
                      "scan_pe: cannot allocate memory for imphash string\n");
            ret = CL_EMEM;
            break;
          }
          j = 0;
          if (!*first)
            fname[j++] = ',';
          for (i = 0; i < dlllen; i++, j++)
            fname[j] = tolower(dllname[i]);
          fname[j++] = '.';
          for (i = 0; i < funclen; i++, j++)
            fname[j] = tolower(funcname[i]);
          if (imptbl) {
            char *jname = *first ? fname : fname + 1;
            cli_jsonstr_nojson(((void *)0), jname);
          }
          for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
            cl_update_hash(hashctx[type], fname, strlen(fname));
          *impsz += strlen(fname);
          *first = 0;
          free(fname);
        }
      } while (0);
      free(funcname);
      if (ret != CL_SUCCESS)
        return ret;
    }
  }

  return CL_SUCCESS;
}

static unsigned int hash_imptbl(cli_ctx *ctx, unsigned char **digest,
                                uint32_t *impsz, int *genhash,
                                struct cli_exe_info *peinfo) {
  struct pe_image_import_descriptor *image;
  fmap_t *map = *ctx->fmap;
  size_t left, fsize = map->len;
  uint32_t impoff, offset;
  const char *impdes, *buffer;
  void *hashctx[CLI_HASH_AVAIL_TYPES];
  enum CLI_HASH_TYPE type;
  int nimps = 0, ret = CL_SUCCESS;
  unsigned int err;
  int first = 1;

  if (peinfo->dirs[1].VirtualAddress == 0 || peinfo->dirs[1].Size == 0) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("scan_pe: import table data dir does not exist "
                              "(skipping .imp scanning)\n");
    return CL_SUCCESS;
  }

  impoff = cli_rawaddr(peinfo->dirs[1].VirtualAddress, peinfo->sections,
                       peinfo->nsections, &err, fsize, peinfo->hdr_size);
  if (err || impoff + peinfo->dirs[1].Size > fsize) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("scan_pe: invalid rva for import table data\n");
    return CL_SUCCESS;
  }

  impdes = fmap_need_off(map, impoff, peinfo->dirs[1].Size);
  if (impdes == ((void *)0)) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("scan_pe: failed to acquire fmap buffer\n");
    return CL_EREAD;
  }
  left = peinfo->dirs[1].Size;

  memset(hashctx, 0, sizeof(hashctx));
  if (genhash[CLI_HASH_MD5]) {
    hashctx[CLI_HASH_MD5] = cl_hash_init("md5");
    if (hashctx[CLI_HASH_MD5] == ((void *)0)) {
      fmap_unneed_off(map, impoff, peinfo->dirs[1].Size);
      return CL_EMEM;
    }
  }
  if (genhash[CLI_HASH_SHA1]) {
    hashctx[CLI_HASH_SHA1] = cl_hash_init("sha1");
    if (hashctx[CLI_HASH_SHA1] == ((void *)0)) {
      fmap_unneed_off(map, impoff, peinfo->dirs[1].Size);
      return CL_EMEM;
    }
  }
  if (genhash[CLI_HASH_SHA256]) {
    hashctx[CLI_HASH_SHA256] = cl_hash_init("sha256");
    if (hashctx[CLI_HASH_SHA256] == ((void *)0)) {
      fmap_unneed_off(map, impoff, peinfo->dirs[1].Size);
      return CL_EMEM;
    }
  }

  image = (struct pe_image_import_descriptor *)impdes;
  while (left > sizeof(struct pe_image_import_descriptor) && image->Name != 0 &&
         nimps < 1024) {
    char *dllname = ((void *)0);

    left -= sizeof(struct pe_image_import_descriptor);
    nimps++;

    image->u.OriginalFirstThunk = ((uint32_t)(
        ((const union unaligned_32 *)(&(image->u.OriginalFirstThunk)))
            ->una_s32));
    image->TimeDateStamp = ((uint32_t)(
        ((const union unaligned_32 *)(&(image->TimeDateStamp)))->una_s32));
    image->ForwarderChain = ((uint32_t)(
        ((const union unaligned_32 *)(&(image->ForwarderChain)))->una_s32));
    image->Name =
        ((uint32_t)(((const union unaligned_32 *)(&(image->Name)))->una_s32));
    image->FirstThunk = ((uint32_t)(
        ((const union unaligned_32 *)(&(image->FirstThunk)))->una_s32));

    offset = cli_rawaddr(image->Name, peinfo->sections, peinfo->nsections, &err,
                         fsize, peinfo->hdr_size);
    if (err || offset > fsize) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("scan_pe: invalid rva for dll name\n");

      ret = CL_EFORMAT;
      goto hash_imptbl_end;
    }

    buffer = fmap_need_off_once(
        map, offset, ((256) < (fsize - offset) ? (256) : (fsize - offset)));
    if (buffer == ((void *)0)) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("scan_pe: failed to read name for dll\n");
      ret = CL_EREAD;
      goto hash_imptbl_end;
    }

    if (validate_impname(dllname,
                         ((256) < (fsize - offset) ? (256) : (fsize - offset)),
                         1) == 0) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("scan_pe: invalid name for imported dll\n");
      ret = CL_EFORMAT;
      goto hash_imptbl_end;
    }

    dllname =
        strndup(buffer, ((256) < (fsize - offset) ? (256) : (fsize - offset)));
    if (dllname == ((void *)0)) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("scan_pe: cannot duplicate dll name\n");
      ret = CL_EMEM;
      goto hash_imptbl_end;
    }

    ret = hash_impfns(ctx, hashctx, impsz, image, dllname, peinfo, &first);
    free(dllname);
    dllname = ((void *)0);
    if (ret != CL_SUCCESS)
      goto hash_imptbl_end;

    image++;
  }

hash_imptbl_end:
  fmap_unneed_off(map, impoff, peinfo->dirs[1].Size);
  for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
    cl_finish_hash(hashctx[type], digest[type]);
  return ret;
}

static int scan_pe_imp(cli_ctx *ctx, struct cli_exe_info *peinfo) {
  struct cli_matcher *imp = ctx->engine->hm_imp;
  unsigned char *hashset[CLI_HASH_AVAIL_TYPES];
  const char *virname = ((void *)0);
  int genhash[CLI_HASH_AVAIL_TYPES];
  uint32_t impsz = 0;
  enum CLI_HASH_TYPE type;
  int ret = CL_CLEAN;

  for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
    genhash[type] = cli_hm_have_any(imp, type);
    if (genhash[type]) {
      hashset[type] = cli_malloc(hashlen[type]);
      if (!hashset[type]) {
        cli_errmsg("scan_pe: cli_malloc failed!\n");
        for (; type > 0;)
          free(hashset[--type]);
        return CL_EMEM;
      }
    } else {
      hashset[type] = ((void *)0);
    }
  }

  if (cli_debug_flag && !genhash[CLI_HASH_MD5]) {

    genhash[CLI_HASH_MD5] = 1;
    hashset[CLI_HASH_MD5] = cli_calloc(hashlen[CLI_HASH_MD5], sizeof(char));
    if (!hashset[CLI_HASH_MD5]) {
      cli_errmsg("scan_pe: cli_malloc failed!\n");
      for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
        free(hashset[type]);
      return CL_EMEM;
    }
  }

  ret = hash_imptbl(ctx, hashset, &impsz, genhash, peinfo);
  if (ret != CL_SUCCESS) {
    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
      free(hashset[type]);
    return ret;
  }

  if (cli_debug_flag) {

    char *dstr =
        cli_str2hex((char *)hashset[CLI_HASH_MD5], hashlen[CLI_HASH_MD5]);
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("IMP: %s:%u\n", dstr ? (char *)dstr : "(NULL)",
                              impsz);

    if (dstr)
      free(dstr);
  }

  for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
    if (cli_hm_scan(hashset[type], impsz, &virname, imp, type) == CL_VIRUS) {
      ret = cli_append_virus(ctx, virname);
      if (ret != CL_CLEAN) {
        if (ret != CL_VIRUS)
          break;
        else if (!(ctx->options->general & 0x1))
          break;
      }
    }
    if (cli_hm_scan_wild(hashset[type], &virname, imp, type) == CL_VIRUS) {
      cli_append_virus(ctx, virname);
      if (ret != CL_CLEAN) {
        if (ret != CL_VIRUS)
          break;
        else if (!(ctx->options->general & 0x1))
          break;
      }
    }
  }

  for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
    free(hashset[type]);
  return ret;
}
int cli_scanpe(cli_ctx *ctx) {
  uint8_t polipos = 0;
  char epbuff[4096], *tempfile;
  uint32_t epsize;
  size_t bytes;
  unsigned int i, j, found, upx_success = 0, err;
  unsigned int ssize = 0, dsize = 0, corrupted_cur;
  int (*upxfn)(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t,
               uint32_t) = ((void *)0);
  const char *src = ((void *)0);
  char *dest = ((void *)0);
  int ndesc, ret = CL_CLEAN, upack = 0;
  size_t fsize;
  struct cli_bc_ctx *bc_ctx;
  fmap_t *map;
  struct cli_pe_hook_data pedata;

  uint32_t viruses_found = 0;

  if (!ctx) {
    cli_errmsg("cli_scanpe: ctx == NULL\n");
    return CL_ENULLARG;
  }
  map = *ctx->fmap;
  fsize = map->len;

  struct cli_exe_info _peinfo;
  struct cli_exe_info *peinfo = &_peinfo;

  uint32_t opts = 0x2 | 0x10;

  if (((ctx->options->heuristic & 0x2) && !ctx->corrupted_input)) {
    opts |= 0x8;
  }

  cli_exe_info_init(peinfo, 0);

  ret = cli_peheader(map, peinfo, opts, ctx);

  if (-2 == ret) {
    if (((ctx->options->heuristic & 0x2) && !ctx->corrupted_input)) {

      ret = cli_append_virus(ctx, "Heuristics.Broken.Executable");
      cli_exe_info_destroy(peinfo);
      return ret;
    }
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_scanpe: PE header appears broken - "
                              "won't attempt .mdb / .imp / PE-specific BC rule "
                              "matching or exe unpacking\n");
    cli_exe_info_destroy(peinfo);
    return CL_CLEAN;

  } else if (-3 == ret) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_scanpe: JSON creation timed out - "
                              "won't attempt .mdb / .imp / PE-specific BC rule "
                              "matching or exe unpacking\n");
    cli_exe_info_destroy(peinfo);
    return CL_ETIMEOUT;
  } else if (-1 == ret) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_scanpe: An error occurred when parsing the PE header - "
              "won't attempt .mdb / .imp / PE-specific BC rule matching or exe "
              "unpacking\n");
    cli_exe_info_destroy(peinfo);
    return CL_CLEAN;
  }

  if (!peinfo->is_pe32plus) {
    if (ctx->dconf->pe & 0x4000)
      upack = (((uint16_t)(((const union unaligned_16 *)(&(
                                peinfo->file_hdr.SizeOfOptionalHeader)))
                               ->una_s16)) == 0x148);
  }
  for (i = 0; i < peinfo->nsections; i++) {

    if (peinfo->sections[i].rsz) {
      if ((ctx->options->general & 0x4) && (ctx->dconf->pe & 0x8) &&
          peinfo->sections[i].vsz > 40000 && peinfo->sections[i].vsz < 70000 &&
          peinfo->sections[i].chr == 0xe0000060)
        polipos = i;

      if ((ctx->dconf->pe & 0x10) && ctx->engine->hm_mdb) {
        ret = scan_pe_mdb(ctx, &(peinfo->sections[i]));
        if (ret != CL_CLEAN) {

          if (ret != CL_VIRUS)
            cli_errmsg("cli_scanpe: scan_pe_mdb failed: %s!\n",
                       cl_strerror(ret));

          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("------------------------------------\n");
          cli_exe_info_destroy(peinfo);
          return ret;
        }
      }
    }
  }

  if (peinfo->is_pe32plus) {
    cli_exe_info_destroy(peinfo);
    return CL_CLEAN;
  }

  epsize = fmap_readn(map, epbuff, peinfo->ep, 4096);
  if (peinfo->overlay_start && peinfo->overlay_size > 0) {
    ret = cli_scanishield(ctx, peinfo->overlay_start, peinfo->overlay_size);
    if (ret != CL_CLEAN) {

      cli_exe_info_destroy(peinfo);
      return ret;
    }
  }

  pedata.nsections = peinfo->nsections;
  pedata.ep = peinfo->ep;
  pedata.offset = 0;
  memcpy(&pedata.file_hdr, &(peinfo->file_hdr), sizeof(peinfo->file_hdr));

  memcpy(&pedata.opt32, &(peinfo->pe_opt.opt32), sizeof(peinfo->pe_opt.opt32));
  memcpy(&pedata.opt64, &(peinfo->pe_opt.opt64), sizeof(peinfo->pe_opt.opt64));
  memcpy(&pedata.dirs, &(peinfo->dirs), sizeof(peinfo->dirs));

  memcpy(&pedata.opt32_dirs, &(peinfo->dirs), sizeof(peinfo->dirs));
  memcpy(&pedata.opt64_dirs, &(peinfo->dirs), sizeof(peinfo->dirs));
  pedata.e_lfanew = peinfo->e_lfanew;
  pedata.overlays = peinfo->overlay_start;
  pedata.overlays_sz = peinfo->overlay_size;
  pedata.hdr_size = peinfo->hdr_size;

  bc_ctx = cli_bytecode_context_alloc();
  if (!bc_ctx) {
    cli_errmsg("cli_scanpe: can't allocate memory for bc_ctx\n");
    cli_exe_info_destroy(peinfo);
    return CL_EMEM;
  }

  cli_bytecode_context_setpe(bc_ctx, &pedata, peinfo->sections);
  cli_bytecode_context_setctx(bc_ctx, ctx);
  ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, BC_PE_ALL, map);
  switch (ret) {
  case CL_ENULLARG:
    cli_warnmsg("cli_scanpe: NULL argument supplied\n");
    break;
  case CL_VIRUS:
  case CL_BREAK:

    cli_exe_info_destroy(peinfo);
    cli_bytecode_context_destroy(bc_ctx);
    return ret == CL_VIRUS ? CL_VIRUS : CL_CLEAN;
  }
  cli_bytecode_context_destroy(bc_ctx);

  if (ctx->dconf->pe & 0x80000 && ctx->engine->hm_imp) {

    ret = scan_pe_imp(ctx, peinfo);
    switch (ret) {
    case CL_SUCCESS:
      break;
    case CL_ENULLARG:
      cli_warnmsg("cli_scanpe: NULL argument supplied\n");
      break;
    case CL_VIRUS:
      if ((ctx->options->general & 0x1))
        break;

    case CL_BREAK:
      cli_exe_info_destroy(peinfo);
      return ret == CL_VIRUS ? CL_VIRUS : CL_CLEAN;
    default:
      cli_exe_info_destroy(peinfo);
      return ret;
    }
  }

  if ((ctx->options->general & 0x4) && (ctx->dconf->pe & 0x1) &&
      !peinfo->is_dll && epsize == 4096 &&
      peinfo->ep == peinfo->sections[peinfo->nsections - 1].raw) {
    const char *pt = cli_memstr(
        epbuff, 4040,
        "\x47\x65\x74\x50\x72\x6f\x63\x41\x64\x64\x72\x65\x73\x73\x00", 15);
    if (pt) {
      pt += 15;
      if ((((uint32_t)(((const union unaligned_32 *)(pt))->una_s32) ^
            (uint32_t)(((const union unaligned_32 *)(pt + 4))->una_s32)) ==
           0x505a4f) &&
          (((uint32_t)(((const union unaligned_32 *)(pt + 8))->una_s32) ^
            (uint32_t)(((const union unaligned_32 *)(pt + 12))->una_s32)) ==
           0xffffb) &&
          (((uint32_t)(((const union unaligned_32 *)(pt + 16))->una_s32) ^
            (uint32_t)(((const union unaligned_32 *)(pt + 20))->una_s32)) ==
           0xb8)) {
        ret = cli_append_virus(ctx, "Heuristics.W32.Parite.B");
        if (ret != CL_CLEAN) {
          if (ret == CL_VIRUS) {
            if (!(ctx->options->general & 0x1)) {
              cli_exe_info_destroy(peinfo);
              return ret;
            } else
              viruses_found++;
          } else {
            cli_exe_info_destroy(peinfo);
            return ret;
          }
        }
      }
    }
  }

  if ((ctx->options->general & 0x4) && (ctx->dconf->pe & 0x2) &&
      epsize >= 200 &&
      ((size_t)(peinfo->sections[peinfo->nsections - 1].rsz) > 0 &&
       (size_t)(0x0fd2) > 0 &&
       (size_t)(0x0fd2) <=
           (size_t)(peinfo->sections[peinfo->nsections - 1].rsz) &&
       (ptrdiff_t)(peinfo->ep) >=
           (ptrdiff_t)(peinfo->sections[peinfo->nsections - 1].raw) &&
       (ptrdiff_t)(peinfo->ep) + (ptrdiff_t)(0x0fd2) <=
           (ptrdiff_t)(peinfo->sections[peinfo->nsections - 1].raw) +
               (ptrdiff_t)(peinfo->sections[peinfo->nsections - 1].rsz) &&
       (ptrdiff_t)(peinfo->ep) + (ptrdiff_t)(0x0fd2) >
           (ptrdiff_t)(peinfo->sections[peinfo->nsections - 1].raw) &&
       (ptrdiff_t)(peinfo->ep) <
           (ptrdiff_t)(peinfo->sections[peinfo->nsections - 1].raw) +
               (ptrdiff_t)(peinfo->sections[peinfo->nsections - 1].rsz)) &&
      epbuff[1] == '\x9c' && epbuff[2] == '\x60') {
    enum {
      KZSTRASH,
      KZSCDELTA,
      KZSPDELTA,
      KZSGETSIZE,
      KZSXORPRFX,
      KZSXOR,
      KZSDDELTA,
      KZSLOOP,
      KZSTOP
    };
    uint8_t kzs[] = {KZSTRASH,  KZSCDELTA,  KZSPDELTA, KZSGETSIZE,
                     KZSTRASH,  KZSXORPRFX, KZSXOR,    KZSTRASH,
                     KZSDDELTA, KZSTRASH,   KZSLOOP,   KZSTOP};
    uint8_t *kzstate = kzs;
    uint8_t *kzcode = (uint8_t *)epbuff + 3;
    uint8_t kzdptr = 0xff, kzdsize = 0xff;
    int kzlen = 197, kzinitlen = 0xffff, kzxorlen = -1;
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_scanpe: in kriz\n");

    while (*kzstate != KZSTOP) {
      uint8_t op;
      if (kzlen <= 6)
        break;

      op = *kzcode++;
      kzlen--;

      switch (*kzstate) {
      case KZSTRASH:
      case KZSGETSIZE: {
        int opsz = 0;
        switch (op) {
        case 0x81:
          kzcode += 5;
          kzlen -= 5;
          break;
        case 0xb8:
        case 0xb9:
        case 0xba:
        case 0xbb:
        case 0xbd:
        case 0xbe:
        case 0xbf:
          if (*kzstate == KZSGETSIZE &&
              (((const union unaligned_32 *)(kzcode))->una_s32) == 0x0fd2) {
            kzinitlen = kzlen - 5;
            kzdsize = op - 0xb8;
            kzstate++;
            op = 4;

            (!__builtin_expect(!!(cli_debug_flag), 0))
                ? (void)0
                : cli_dbgmsg_internal(
                      "cli_scanpe: kriz: using #%d as size counter\n", kzdsize);
          }
          opsz = 4;
        case 0x48:
        case 0x49:
        case 0x4a:
        case 0x4b:
        case 0x4d:
        case 0x4e:
        case 0x4f:
          op &= 7;
          if (op != kzdptr && op != kzdsize) {
            kzcode += opsz;
            kzlen -= opsz;
            break;
          }
        default:
          kzcode--;
          kzlen++;
          kzstate++;
        }

        break;
      }
      case KZSCDELTA:
        if (op == 0xe8 &&
            (uint32_t)(((const union unaligned_32 *)(kzcode))->una_s32) <
                0xff) {
          kzlen -= *kzcode + 4;
          kzcode += *kzcode + 4;
          kzstate++;
        } else {
          *kzstate = KZSTOP;
        }

        break;
      case KZSPDELTA:
        if ((op & 0xf8) == 0x58 && (kzdptr = op - 0x58) != 4) {
          kzstate++;
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("cli_scanpe: kriz: using #%d as pointer\n",
                                    kzdptr);
        } else {
          *kzstate = KZSTOP;
        }

        break;
      case KZSXORPRFX:
        kzstate++;
        if (op == 0x3e)
          break;
      case KZSXOR:
        if (op == 0x80 && *kzcode == kzdptr + 0xb0) {
          kzxorlen = kzlen;
          kzcode += +6;
          kzlen -= +6;
          kzstate++;
        } else {
          *kzstate = KZSTOP;
        }

        break;
      case KZSDDELTA:
        if (op == kzdptr + 0x48)
          kzstate++;
        else
          *kzstate = KZSTOP;

        break;
      case KZSLOOP:
        if (op == kzdsize + 0x48 && *kzcode == 0x75 &&
            kzlen - (int8_t)kzcode[1] - 3 <= kzinitlen &&
            kzlen - (int8_t)kzcode[1] >= kzxorlen) {
          ret = cli_append_virus(ctx, "Heuristics.W32.Kriz");
          if (ret != CL_CLEAN) {
            if (ret == CL_VIRUS) {
              if (!(ctx->options->general & 0x1)) {
                cli_exe_info_destroy(peinfo);
                return ret;
              } else
                viruses_found++;
            } else {
              cli_exe_info_destroy(peinfo);
              return ret;
            }
          }
        }
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: kriz: loop out of bounds, corrupted sample?\n");
        kzstate++;
      }
    }
  }

  if ((ctx->options->general & 0x4) && (ctx->dconf->pe & 0x4) &&
      !peinfo->is_dll && (peinfo->nsections > 1) &&
      (peinfo->sections[peinfo->nsections - 1].chr & 0x80000000)) {
    uint32_t rsize, vsize, dam = 0;

    vsize = peinfo->sections[peinfo->nsections - 1].uvsz;
    rsize = peinfo->sections[peinfo->nsections - 1].rsz;
    if (rsize < peinfo->sections[peinfo->nsections - 1].ursz) {
      rsize = peinfo->sections[peinfo->nsections - 1].ursz;
      dam = 1;
    }

    if (vsize >= 0x612c && rsize >= 0x612c && ((vsize & 0xff) == 0xec)) {
      int bw = rsize < 0x7000 ? rsize : 0x7000;
      const char *tbuff;

      if ((tbuff = fmap_need_off_once(
               map, peinfo->sections[peinfo->nsections - 1].raw + rsize - bw,
               4096))) {
        if (cli_memstr(tbuff, 4091, "\xe8\x2c\x61\x00\x00", 5)) {
          ret = cli_append_virus(ctx, dam ? "Heuristics.W32.Magistr.A.dam"
                                          : "Heuristics.W32.Magistr.A");
          if (ret != CL_CLEAN) {
            if (ret == CL_VIRUS) {
              if (!(ctx->options->general & 0x1)) {
                cli_exe_info_destroy(peinfo);
                return ret;
              } else
                viruses_found++;
            } else {
              cli_exe_info_destroy(peinfo);
              return ret;
            }
          }
        }
      }
    } else if (rsize >= 0x7000 && vsize >= 0x7000 && ((vsize & 0xff) == 0xed)) {
      int bw = rsize < 0x8000 ? rsize : 0x8000;
      const char *tbuff;

      if ((tbuff = fmap_need_off_once(
               map, peinfo->sections[peinfo->nsections - 1].raw + rsize - bw,
               4096))) {
        if (cli_memstr(tbuff, 4091, "\xe8\x04\x72\x00\x00", 5)) {
          ret = cli_append_virus(ctx, dam ? "Heuristics.W32.Magistr.B.dam"
                                          : "Heuristics.W32.Magistr.B");
          if (ret != CL_CLEAN) {
            if (ret == CL_VIRUS) {
              if (!(ctx->options->general & 0x1)) {
                cli_exe_info_destroy(peinfo);
                return ret;
              } else
                viruses_found++;
            } else {
              cli_exe_info_destroy(peinfo);
              return ret;
            }
          }
        }
      }
    }
  }

  while (polipos && !peinfo->is_dll && peinfo->nsections > 2 &&
         peinfo->nsections < 13 && peinfo->e_lfanew <= 0x800 &&
         (((uint16_t)(
              ((const union unaligned_16 *)(&(peinfo->pe_opt.opt32.Subsystem)))
                  ->una_s16)) == 2 ||
          ((uint16_t)(
              ((const union unaligned_16 *)(&(peinfo->pe_opt.opt32.Subsystem)))
                  ->una_s16)) == 3) &&
         ((uint16_t)(((const union unaligned_16 *)(&(peinfo->file_hdr.Machine)))
                         ->una_s16)) == 0x14c &&
         peinfo->pe_opt.opt32.SizeOfStackReserve >= 0x80000) {
    uint32_t jump, jold, *jumps = ((void *)0);
    const uint8_t *code;
    unsigned int xsjs = 0;

    if (peinfo->sections[0].rsz > (182 * 1024 * 1024))
      break;
    if (peinfo->sections[0].rsz < 5)
      break;
    if (!(code = fmap_need_off_once(map, peinfo->sections[0].raw,
                                    peinfo->sections[0].rsz)))
      break;

    for (i = 0; i < peinfo->sections[0].rsz - 5; i++) {
      if ((uint8_t)(code[i] - 0xe8) > 1)
        continue;

      jump = cli_rawaddr(
          peinfo->sections[0].rva + i + 5 +
              (((const union unaligned_32 *)(&code[i + 1]))->una_s32),
          peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
      if (err ||
          !((size_t)(peinfo->sections[polipos].rsz) > 0 && (size_t)(9) > 0 &&
            (size_t)(9) <= (size_t)(peinfo->sections[polipos].rsz) &&
            (ptrdiff_t)(jump) >= (ptrdiff_t)(peinfo->sections[polipos].raw) &&
            (ptrdiff_t)(jump) + (ptrdiff_t)(9) <=
                (ptrdiff_t)(peinfo->sections[polipos].raw) +
                    (ptrdiff_t)(peinfo->sections[polipos].rsz) &&
            (ptrdiff_t)(jump) + (ptrdiff_t)(9) >
                (ptrdiff_t)(peinfo->sections[polipos].raw) &&
            (ptrdiff_t)(jump) < (ptrdiff_t)(peinfo->sections[polipos].raw) +
                                    (ptrdiff_t)(peinfo->sections[polipos].rsz)))
        continue;

      if (xsjs % 128 == 0) {
        if (xsjs == 1280)
          break;

        if (!(jumps = (uint32_t *)cli_realloc2(jumps, (xsjs + 128) *
                                                          sizeof(uint32_t)))) {
          cli_exe_info_destroy(peinfo);
          return CL_EMEM;
        }
      }

      j = 0;
      for (; j < xsjs; j++) {
        if (jumps[j] < jump)
          continue;
        if (jumps[j] == jump) {
          xsjs--;
          break;
        }

        jold = jumps[j];
        jumps[j] = jump;
        jump = jold;
      }

      jumps[j] = jump;
      xsjs++;
    }

    if (!xsjs)
      break;

    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_scanpe: Polipos: Checking %d xsect jump(s)\n", xsjs);
    for (i = 0; i < xsjs; i++) {
      if (!(code = fmap_need_off_once(map, jumps[i], 9)))
        continue;

      if ((jump = (((const union unaligned_32 *)(code))->una_s32)) ==
              0x60ec8b55 ||
          (code[4] == 0x0ec &&
           ((jump == 0x83ec8b55 && code[6] == 0x60) ||
            (jump == 0x81ec8b55 && !code[7] && !code[8])))) {
        ret = cli_append_virus(ctx, "Heuristics.W32.Polipos.A");
        if (ret != CL_CLEAN) {
          if (ret == CL_VIRUS) {
            if (!(ctx->options->general & 0x1)) {
              free(jumps);
              cli_exe_info_destroy(peinfo);
              return ret;
            } else
              viruses_found++;
          } else {
            free(jumps);
            cli_exe_info_destroy(peinfo);
            return ret;
          }
        }
      }
    }

    free(jumps);
    break;
  }

  if ((ctx->options->general & 0x4) && (ctx->dconf->pe & 0x80) &&
      peinfo->nsections > 1 && fsize > 64 * 1024 && fsize < 4 * 1024 * 1024) {
    if (peinfo->dirs[2].Size) {
      struct swizz_stats *stats = cli_calloc(1, sizeof(*stats));
      unsigned int m = 1000;
      ret = CL_CLEAN;

      if (!stats) {
        cli_exe_info_destroy(peinfo);
        return CL_EMEM;
      } else {
        cli_parseres_special(((uint32_t)(((const union unaligned_32 *)(&(
                                              peinfo->dirs[2].VirtualAddress)))
                                             ->una_s32)),
                             ((uint32_t)(((const union unaligned_32 *)(&(
                                              peinfo->dirs[2].VirtualAddress)))
                                             ->una_s32)),
                             map, peinfo, fsize, 0, 0, &m, stats);
        if ((ret = cli_detect_swizz(stats)) == CL_VIRUS) {
          ret = cli_append_virus(ctx, "Heuristics.Trojan.Swizzor.Gen");
          if (ret != CL_CLEAN) {
            if (ret == CL_VIRUS) {
              if (!(ctx->options->general & 0x1)) {
                free(stats);
                cli_exe_info_destroy(peinfo);
                return ret;
              } else
                viruses_found++;
            } else {
              free(stats);
              cli_exe_info_destroy(peinfo);
              return ret;
            }
          }
        }
      }
    }
  }

  corrupted_cur = ctx->corrupted_input;
  ctx->corrupted_input = 2;

  found = 0;
  if (ctx->dconf->pe & (0x20 | 0x40 | 0x2000)) {
    for (i = 0; i < (unsigned int)peinfo->nsections - 1; i++) {
      if (!peinfo->sections[i].rsz && peinfo->sections[i].vsz &&
          peinfo->sections[i + 1].rsz && peinfo->sections[i + 1].vsz) {
        found = 1;
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: UPX/FSG/MEW: empty section "
                                  "found - assuming compression\n");

        break;
      }
    }
  }

  if (found && (ctx->dconf->pe & 0x2000) && epsize >= 16 &&
      epbuff[0] == '\xe9') {
    uint32_t fileoffset;
    const char *tbuff;

    fileoffset = (peinfo->vep +
                  (((const union unaligned_32 *)(epbuff + 1))->una_s32) + 5);
    while (fileoffset == 0x154 || fileoffset == 0x158) {
      char *src;
      uint32_t offdiff, uselzma;

      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: MEW: found MEW characteristics %08X + %08X + 5 = "
                "%08X\n",
                (((const union unaligned_32 *)(epbuff + 1))->una_s32),
                peinfo->vep,
                (((const union unaligned_32 *)(epbuff + 1))->una_s32) +
                    peinfo->vep + 5);

      if (!(tbuff = fmap_need_off_once(map, fileoffset, 0xb0)))
        break;

      if (fileoffset == 0x154)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: MEW: Win9x compatibility was set!\n");
      else
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: MEW: Win9x compatibility was NOT set!\n");

      offdiff =
          (((const union unaligned_32 *)(tbuff + 1))->una_s32) -
          ((uint32_t)(
              ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                  ->una_s32));
      if ((offdiff <= peinfo->sections[i + 1].rva) ||
          (offdiff >=
           peinfo->sections[i + 1].rva + peinfo->sections[i + 1].raw - 4)) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: MEW: ESI is not in proper section\n");
        break;
      }

      offdiff -= peinfo->sections[i + 1].rva;

      if (!peinfo->sections[i + 1].rsz) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: MEW: mew section is empty\n");
        break;
      }

      ssize = peinfo->sections[i + 1].vsz;
      dsize = peinfo->sections[i].vsz;

      if ((ssize + dsize < ssize) || (ssize + dsize < dsize)) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: MEW: section size (%08x) + diff size (%08x) "
                  "exceeds max size of unsigned int (%08x)\n",
                  ssize, dsize, (4294967295U));
        break;
      }

      if (offdiff >= ssize + dsize) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: MEW: offdiff (%08x) exceeds "
                                  "section size + diff size (%08x)\n",
                                  offdiff, ssize + dsize);
        break;
      }

      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: MEW: ssize %08x dsize %08x offdiff: %08x\n", ssize,
                dsize, offdiff);

      if (cli_checklimits("cli_scanpe: MEW", ctx,
                          (((ssize) > (dsize) ? (ssize) : (dsize))), 0,
                          0) != CL_CLEAN) {
        cli_exe_info_destroy(peinfo);
        return CL_CLEAN;
      };
      if (cli_checklimits("cli_scanpe: MEW", ctx,
                          (((ssize + dsize) > (peinfo->sections[i + 1].rsz)
                                ? (ssize + dsize)
                                : (peinfo->sections[i + 1].rsz))),
                          0, 0) != CL_CLEAN) {
        cli_exe_info_destroy(peinfo);
        return CL_CLEAN;
      };

      if (peinfo->sections[i + 1].rsz < offdiff + 12 ||
          peinfo->sections[i + 1].rsz > ssize) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: MEW: Size mismatch: %08x\n",
                                  peinfo->sections[i + 1].rsz);
        break;
      }

      if (!(src = cli_calloc(ssize + dsize, sizeof(char)))) {
        cli_exe_info_destroy(peinfo);
        return CL_EMEM;
      }

      bytes = fmap_readn(map, src + dsize, peinfo->sections[i + 1].raw,
                         peinfo->sections[i + 1].rsz);
      if (bytes != peinfo->sections[i + 1].rsz) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: MEW: Can't read %u bytes [read: %zu]\n",
                  peinfo->sections[i + 1].rsz, bytes);
        cli_exe_info_destroy(peinfo);
        free(src);
        return CL_EREAD;
      }

      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: MEW: %zu (%08zx) bytes read\n",
                                bytes, bytes);

      if (tbuff[0x7b] == '\xe8') {
        if (!((size_t)(peinfo->sections[1].vsz) > 0 && (size_t)(4) > 0 &&
              (size_t)(4) <= (size_t)(peinfo->sections[1].vsz) &&
              (ptrdiff_t)(
                  (((const union unaligned_32 *)(tbuff + 0x7c))->una_s32) +
                  fileoffset + 0x80) >= (ptrdiff_t)(peinfo->sections[1].rva) &&
              (ptrdiff_t)(
                  (((const union unaligned_32 *)(tbuff + 0x7c))->una_s32) +
                  fileoffset + 0x80) +
                      (ptrdiff_t)(4) <=
                  (ptrdiff_t)(peinfo->sections[1].rva) +
                      (ptrdiff_t)(peinfo->sections[1].vsz) &&
              (ptrdiff_t)(
                  (((const union unaligned_32 *)(tbuff + 0x7c))->una_s32) +
                  fileoffset + 0x80) +
                      (ptrdiff_t)(4) >
                  (ptrdiff_t)(peinfo->sections[1].rva) &&
              (ptrdiff_t)(
                  (((const union unaligned_32 *)(tbuff + 0x7c))->una_s32) +
                  fileoffset + 0x80) <
                  (ptrdiff_t)(peinfo->sections[1].rva) +
                      (ptrdiff_t)(peinfo->sections[1].vsz))) {
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal(
                    "cli_scanpe: MEW: lzma proc out of bounds!\n");
          free(src);
          break;
        }

        uselzma = (((const union unaligned_32 *)(tbuff + 0x7c))->una_s32) -
                  (peinfo->sections[0].rva - fileoffset - 0x80);
      } else {
        uselzma = 0;
      }

      if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
        cli_exe_info_destroy(peinfo);
        cli_multifree(src, 0);
        return CL_EMEM;
      }
      if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: MEW"
                                  ": Can't create file %s\n",
                                  tempfile);
        free(tempfile);
        cli_exe_info_destroy(peinfo);
        cli_multifree(src, 0);
        return CL_ECREAT;
      };
      switch ((unmew11(src, offdiff, ssize, dsize,
                       ((uint32_t)(((const union unaligned_32 *)(&(
                                        peinfo->pe_opt.opt32.ImageBase)))
                                       ->una_s32)),
                       peinfo->sections[0].rva, uselzma, ndesc))) {
      case 1:
        if (ctx->engine->keeptmp)
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal(
                    "cli_scanpe: MEW"
                    ": Unpacked and rebuilt executable saved in %s\n",
                    tempfile);
        else
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("cli_scanpe: MEW"
                                    ": Unpacked and rebuilt executable\n");
        cli_multifree(src, 0);
        cli_exe_info_destroy(peinfo);
        lseek(ndesc, 0, 0);
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
        do {
        } while (0);
        if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) ==
            CL_VIRUS) {
          close(ndesc);
          do {
          } while (0);
          if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile)) {
              free(tempfile);
              return CL_EUNLINK;
            }
          };
          free(tempfile);
          return CL_VIRUS;
        }
        do {
        } while (0);
        close(ndesc);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_CLEAN;
        (void)0;
      default:
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: MEW"
                                  ": Unpacking failed\n");
        close(ndesc);
        if (cli_unlink(tempfile)) {
          cli_exe_info_destroy(peinfo);
          free(tempfile);
          cli_multifree(src, 0);
          return CL_EUNLINK;
        }
        cli_multifree(src, 0);
        free(tempfile);
      };
      break;
    }
  }

  if (epsize < 168) {
    cli_exe_info_destroy(peinfo);
    return CL_CLEAN;
  }

  if (found || upack) {
    while (((upack && peinfo->nsections == 3) &&
            ((epbuff[0] == '\xbe' &&
              (((const union unaligned_32 *)(epbuff + 1))->una_s32) -
                      ((uint32_t)(((const union unaligned_32 *)(&(
                                       peinfo->pe_opt.opt32.ImageBase)))
                                      ->una_s32)) >
                  peinfo->min &&
              epbuff[5] == '\xad' && epbuff[6] == '\x50') ||

             (epbuff[0] == '\xbe' &&
              (((const union unaligned_32 *)(epbuff + 1))->una_s32) -
                      ((uint32_t)(((const union unaligned_32 *)(&(
                                       peinfo->pe_opt.opt32.ImageBase)))
                                      ->una_s32)) >
                  peinfo->min &&
              epbuff[5] == '\xff' && epbuff[6] == '\x36'))) ||
           ((!upack && peinfo->nsections == 2) &&
            ((epbuff[0] == '\x60' && epbuff[1] == '\xe8' &&
              (((const union unaligned_32 *)(epbuff + 2))->una_s32) == 0x9) ||
             (epbuff[0] == '\xbe' &&
              (((const union unaligned_32 *)(epbuff + 1))->una_s32) -
                      ((uint32_t)(((const union unaligned_32 *)(&(
                                       peinfo->pe_opt.opt32.ImageBase)))
                                      ->una_s32)) <
                  peinfo->min &&
              (((const union unaligned_32 *)(epbuff + 1))->una_s32) -
                      ((uint32_t)(((const union unaligned_32 *)(&(
                                       peinfo->pe_opt.opt32.ImageBase)))
                                      ->una_s32)) >
                  0 &&
              epbuff[5] == '\xad' && epbuff[6] == '\x8b' &&
              epbuff[7] == '\xf8')))) {
      uint32_t vma, off;
      int a, b, c;

      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: Upack characteristics found.\n");
      a = peinfo->sections[0].vsz;
      b = peinfo->sections[1].vsz;
      if (upack) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: Upack: var set\n");

        c = peinfo->sections[2].vsz;
        ssize = peinfo->sections[0].ursz + peinfo->sections[0].uraw;
        off = peinfo->sections[0].rva;
        vma = ((uint32_t)(((const union unaligned_32 *)(&(
                               peinfo->pe_opt.opt32.ImageBase)))
                              ->una_s32)) +
              peinfo->sections[0].rva;
      } else {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: Upack: var NOT set\n");
        c = peinfo->sections[1].rva;
        ssize = peinfo->sections[1].uraw;
        off = 0;
        vma = peinfo->sections[1].rva - peinfo->sections[1].uraw;
      }

      dsize = a + b + c;

      if (cli_checklimits("cli_scanpe: Upack", ctx,
                          (((((dsize) > (ssize) ? (dsize) : (ssize))) >
                                    (peinfo->sections[1].ursz)
                                ? (((dsize) > (ssize) ? (dsize) : (ssize)))
                                : (peinfo->sections[1].ursz))),
                          0, 0) != CL_CLEAN) {
        cli_exe_info_destroy(peinfo);
        return CL_CLEAN;
      };

      if (!((size_t)(dsize) > 0 && (size_t)(peinfo->sections[1].ursz) > 0 &&
            (size_t)(peinfo->sections[1].ursz) <= (size_t)(dsize) &&
            (ptrdiff_t)(peinfo->sections[1].rva - off) >= (ptrdiff_t)(0) &&
            (ptrdiff_t)(peinfo->sections[1].rva - off) +
                    (ptrdiff_t)(peinfo->sections[1].ursz) <=
                (ptrdiff_t)(0) + (ptrdiff_t)(dsize) &&
            (ptrdiff_t)(peinfo->sections[1].rva - off) +
                    (ptrdiff_t)(peinfo->sections[1].ursz) >
                (ptrdiff_t)(0) &&
            (ptrdiff_t)(peinfo->sections[1].rva - off) <
                (ptrdiff_t)(0) + (ptrdiff_t)(dsize)) ||
          (upack &&
           !((size_t)(dsize) > 0 && (size_t)(ssize) > 0 &&
             (size_t)(ssize) <= (size_t)(dsize) &&
             (ptrdiff_t)(peinfo->sections[2].rva - peinfo->sections[0].rva) >=
                 (ptrdiff_t)(0) &&
             (ptrdiff_t)(peinfo->sections[2].rva - peinfo->sections[0].rva) +
                     (ptrdiff_t)(ssize) <=
                 (ptrdiff_t)(0) + (ptrdiff_t)(dsize) &&
             (ptrdiff_t)(peinfo->sections[2].rva - peinfo->sections[0].rva) +
                     (ptrdiff_t)(ssize) >
                 (ptrdiff_t)(0) &&
             (ptrdiff_t)(peinfo->sections[2].rva - peinfo->sections[0].rva) <
                 (ptrdiff_t)(0) + (ptrdiff_t)(dsize))) ||
          ssize > dsize) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: Upack: probably malformed "
                                  "pe-header, skipping to next unpacker\n");
        break;
      }

      if ((dest = (char *)cli_calloc(dsize, sizeof(char))) == ((void *)0)) {
        cli_exe_info_destroy(peinfo);
        return CL_EMEM;
      }

      if (fmap_readn(map, dest, 0, ssize) != ssize) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: Upack: Can't read raw data of section 0\n");
        free(dest);
        break;
      }

      if (upack)
        memmove(dest + peinfo->sections[2].rva - peinfo->sections[0].rva, dest,
                ssize);

      if (fmap_readn(map, dest + peinfo->sections[1].rva - off,
                     peinfo->sections[1].uraw,
                     peinfo->sections[1].ursz) != peinfo->sections[1].ursz) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: Upack: Can't read raw data of section 1\n");
        free(dest);
        break;
      }

      if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
        cli_exe_info_destroy(peinfo);
        cli_multifree(dest, 0);
        return CL_EMEM;
      }
      if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: Upack"
                                  ": Can't create file %s\n",
                                  tempfile);
        free(tempfile);
        cli_exe_info_destroy(peinfo);
        cli_multifree(dest, 0);
        return CL_ECREAT;
      };
      switch ((unupack(upack, dest, dsize, epbuff, vma, peinfo->ep,
                       ((uint32_t)(((const union unaligned_32 *)(&(
                                        peinfo->pe_opt.opt32.ImageBase)))
                                       ->una_s32)),
                       peinfo->sections[0].rva, ndesc))) {
      case 1:
        if (ctx->engine->keeptmp)
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal(
                    "cli_scanpe: Upack"
                    ": Unpacked and rebuilt executable saved in %s\n",
                    tempfile);
        else
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("cli_scanpe: Upack"
                                    ": Unpacked and rebuilt executable\n");
        cli_multifree(dest, 0);
        cli_exe_info_destroy(peinfo);
        lseek(ndesc, 0, 0);
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
        do {
        } while (0);
        if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) ==
            CL_VIRUS) {
          close(ndesc);
          do {
          } while (0);
          if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile)) {
              free(tempfile);
              return CL_EUNLINK;
            }
          };
          free(tempfile);
          return CL_VIRUS;
        }
        do {
        } while (0);
        close(ndesc);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_CLEAN;
        (void)0;
      default:
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: Upack"
                                  ": Unpacking failed\n");
        close(ndesc);
        if (cli_unlink(tempfile)) {
          cli_exe_info_destroy(peinfo);
          free(tempfile);
          cli_multifree(dest, 0);
          return CL_EUNLINK;
        }
        cli_multifree(dest, 0);
        free(tempfile);
      };

      break;
    }
  }

  while (found && (ctx->dconf->pe & 0x40) && epbuff[0] == '\x87' &&
         epbuff[1] == '\x25') {
    const char *dst;
    uint32_t newesi, newedi, newebx, newedx;

    ssize = peinfo->sections[i + 1].rsz;
    dsize = peinfo->sections[i].vsz;

    if (cli_checklimits("cli_scanpe: FSG", ctx,
                        (((dsize) > (ssize) ? (dsize) : (ssize))), 0,
                        0) != CL_CLEAN) {
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    };

    if (ssize <= 0x19 || dsize <= ssize) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Size mismatch (ssize: %d, dsize: %d)\n",
                ssize, dsize);
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    }

    newedx =
        (((const union unaligned_32 *)(epbuff + 2))->una_s32) -
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32));
    if (!((size_t)(peinfo->sections[i + 1].rsz) > 0 && (size_t)(4) > 0 &&
          (size_t)(4) <= (size_t)(peinfo->sections[i + 1].rsz) &&
          (ptrdiff_t)(newedx) >= (ptrdiff_t)(peinfo->sections[i + 1].rva) &&
          (ptrdiff_t)(newedx) + (ptrdiff_t)(4) <=
              (ptrdiff_t)(peinfo->sections[i + 1].rva) +
                  (ptrdiff_t)(peinfo->sections[i + 1].rsz) &&
          (ptrdiff_t)(newedx) + (ptrdiff_t)(4) >
              (ptrdiff_t)(peinfo->sections[i + 1].rva) &&
          (ptrdiff_t)(newedx) < (ptrdiff_t)(peinfo->sections[i + 1].rva) +
                                    (ptrdiff_t)(peinfo->sections[i + 1].rsz))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: xchg out of bounds (%x), giving up\n",
                newedx);
      break;
    }

    if (!peinfo->sections[i + 1].rsz ||
        !(src = fmap_need_off_once(map, peinfo->sections[i + 1].raw, ssize))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: Can't read raw data of section %d\n", i + 1);
      cli_exe_info_destroy(peinfo);
      return CL_ESEEK;
    }

    dst = src + newedx - peinfo->sections[i + 1].rva;
    if (newedx < peinfo->sections[i + 1].rva ||
        !((size_t)(ssize) > 0 && (size_t)(4) > 0 &&
          (size_t)(4) <= (size_t)(ssize) &&
          (ptrdiff_t)(dst) >= (ptrdiff_t)(src) &&
          (ptrdiff_t)(dst) + (ptrdiff_t)(4) <=
              (ptrdiff_t)(src) + (ptrdiff_t)(ssize) &&
          (ptrdiff_t)(dst) + (ptrdiff_t)(4) > (ptrdiff_t)(src) &&
          (ptrdiff_t)(dst) < (ptrdiff_t)(src) + (ptrdiff_t)(ssize))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG: New ESP out of bounds\n");
      break;
    }

    newedx =
        (((const union unaligned_32 *)(dst))->una_s32) -
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32));
    if (!((size_t)(peinfo->sections[i + 1].rsz) > 0 && (size_t)(4) > 0 &&
          (size_t)(4) <= (size_t)(peinfo->sections[i + 1].rsz) &&
          (ptrdiff_t)(newedx) >= (ptrdiff_t)(peinfo->sections[i + 1].rva) &&
          (ptrdiff_t)(newedx) + (ptrdiff_t)(4) <=
              (ptrdiff_t)(peinfo->sections[i + 1].rva) +
                  (ptrdiff_t)(peinfo->sections[i + 1].rsz) &&
          (ptrdiff_t)(newedx) + (ptrdiff_t)(4) >
              (ptrdiff_t)(peinfo->sections[i + 1].rva) &&
          (ptrdiff_t)(newedx) < (ptrdiff_t)(peinfo->sections[i + 1].rva) +
                                    (ptrdiff_t)(peinfo->sections[i + 1].rsz))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG: New ESP (%x) is wrong\n",
                                newedx);
      break;
    }

    dst = src + newedx - peinfo->sections[i + 1].rva;
    if (!((size_t)(ssize) > 0 && (size_t)(32) > 0 &&
          (size_t)(32) <= (size_t)(ssize) &&
          (ptrdiff_t)(dst) >= (ptrdiff_t)(src) &&
          (ptrdiff_t)(dst) + (ptrdiff_t)(32) <=
              (ptrdiff_t)(src) + (ptrdiff_t)(ssize) &&
          (ptrdiff_t)(dst) + (ptrdiff_t)(32) > (ptrdiff_t)(src) &&
          (ptrdiff_t)(dst) < (ptrdiff_t)(src) + (ptrdiff_t)(ssize))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG: New stack out of bounds\n");
      break;
    }

    newedi =
        (((const union unaligned_32 *)(dst))->una_s32) -
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32));
    newesi =
        (((const union unaligned_32 *)(dst + 4))->una_s32) -
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32));
    newebx =
        (((const union unaligned_32 *)(dst + 16))->una_s32) -
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32));
    newedx = (((const union unaligned_32 *)(dst + 20))->una_s32);

    if (newedi != peinfo->sections[i].rva) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG: Bad destination buffer (edi "
                                "is %x should be %x)\n",
                                newedi, peinfo->sections[i].rva);
      break;
    }

    if (newesi < peinfo->sections[i + 1].rva ||
        newesi - peinfo->sections[i + 1].rva >= peinfo->sections[i + 1].rsz) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Source buffer out of section bounds\n");
      break;
    }

    if (!((size_t)(peinfo->sections[i + 1].rsz) > 0 && (size_t)(16) > 0 &&
          (size_t)(16) <= (size_t)(peinfo->sections[i + 1].rsz) &&
          (ptrdiff_t)(newebx) >= (ptrdiff_t)(peinfo->sections[i + 1].rva) &&
          (ptrdiff_t)(newebx) + (ptrdiff_t)(16) <=
              (ptrdiff_t)(peinfo->sections[i + 1].rva) +
                  (ptrdiff_t)(peinfo->sections[i + 1].rsz) &&
          (ptrdiff_t)(newebx) + (ptrdiff_t)(16) >
              (ptrdiff_t)(peinfo->sections[i + 1].rva) &&
          (ptrdiff_t)(newebx) < (ptrdiff_t)(peinfo->sections[i + 1].rva) +
                                    (ptrdiff_t)(peinfo->sections[i + 1].rsz))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Array of functions out of bounds\n");
      break;
    }

    newedx =
        (((const union unaligned_32 *)(newebx + 12 -
                                       peinfo->sections[i + 1].rva + src))
             ->una_s32) -
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32));
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_scanpe: FSG: found old EP @%x\n", newedx);

    if ((dest = (char *)cli_calloc(dsize, sizeof(char))) == ((void *)0)) {
      cli_exe_info_destroy(peinfo);
      return CL_EMEM;
    }

    if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
      cli_exe_info_destroy(peinfo);
      cli_multifree(dest, 0);
      return CL_EMEM;
    }
    if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG"
                                ": Can't create file %s\n",
                                tempfile);
      free(tempfile);
      cli_exe_info_destroy(peinfo);
      cli_multifree(dest, 0);
      return CL_ECREAT;
    };
    switch ((unfsg_200(
        newesi - peinfo->sections[i + 1].rva + src, dest,
        ssize + peinfo->sections[i + 1].rva - newesi, dsize, newedi,
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32)),
        newedx, ndesc))) {
    case 1:
      if (ctx->engine->keeptmp)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: FSG"
                  ": Unpacked and rebuilt executable saved in %s\n",
                  tempfile);
      else
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: FSG"
                                  ": Unpacked and rebuilt executable\n");
      cli_multifree(dest, 0);
      cli_exe_info_destroy(peinfo);
      lseek(ndesc, 0, 0);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
      do {
      } while (0);
      if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) == CL_VIRUS) {
        close(ndesc);
        do {
        } while (0);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_VIRUS;
      }
      do {
      } while (0);
      close(ndesc);
      if (!ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
          free(tempfile);
          return CL_EUNLINK;
        }
      };
      free(tempfile);
      return CL_CLEAN;
    case 0:
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG"
                                ": Successfully decompressed\n");
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        (void)0;
        return CL_EUNLINK;
      }
      free(tempfile);
      (void)0;
      found = 0;
      upx_success = 1;
      break;
      ;
    default:
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG"
                                ": Unpacking failed\n");
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        cli_multifree(dest, 0);
        return CL_EUNLINK;
      }
      cli_multifree(dest, 0);
      free(tempfile);
    };
    break;
  }

  while (found && (ctx->dconf->pe & 0x40) && epbuff[0] == '\xbe' &&
         (((const union unaligned_32 *)(epbuff + 1))->una_s32) -
                 ((uint32_t)(((const union unaligned_32 *)(&(
                                  peinfo->pe_opt.opt32.ImageBase)))
                                 ->una_s32)) <
             peinfo->min) {
    int sectcnt = 0;
    const char *support;
    uint32_t newesi, newedi, oldep, gp, t;
    struct cli_exe_section *sections;

    ssize = peinfo->sections[i + 1].rsz;
    dsize = peinfo->sections[i].vsz;

    if (cli_checklimits("cli_scanpe: FSG", ctx,
                        (((dsize) > (ssize) ? (dsize) : (ssize))), 0,
                        0) != CL_CLEAN) {
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    };

    if (ssize <= 0x19 || dsize <= ssize) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Size mismatch (ssize: %d, dsize: %d)\n",
                ssize, dsize);
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    }

    if (!(t = cli_rawaddr(
              (((const union unaligned_32 *)(epbuff + 1))->una_s32) -
                  ((uint32_t)(((const union unaligned_32 *)(&(
                                   peinfo->pe_opt.opt32.ImageBase)))
                                  ->una_s32)),
              ((void *)0), 0, &err, fsize, peinfo->hdr_size)) &&
        err) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Support data out of padding area\n");
      break;
    }

    gp = peinfo->sections[i + 1].raw - t;

    if (cli_checklimits("cli_scanpe: FSG", ctx, (gp), 0, 0) != CL_CLEAN) {
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    };

    if (!(support = fmap_need_off_once(map, t, gp))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: Can't read %d bytes from padding area\n", gp);
      cli_exe_info_destroy(peinfo);
      return CL_EREAD;
    }

    newedi =
        (((const union unaligned_32 *)(support + 4))->una_s32) -
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32));
    newesi =
        (((const union unaligned_32 *)(support + 8))->una_s32) -
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32));

    if (newesi < peinfo->sections[i + 1].rva ||
        newesi - peinfo->sections[i + 1].rva >= peinfo->sections[i + 1].rsz) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Source buffer out of section bounds\n");
      break;
    }

    if (newedi != peinfo->sections[i].rva) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Bad destination (is %x should be %x)\n",
                newedi, peinfo->sections[i].rva);
      break;
    }

    for (t = 12; t < gp - 4; t += 4) {
      uint32_t rva = (((const union unaligned_32 *)(support + t))->una_s32);

      if (!rva)
        break;

      rva -=
          ((uint32_t)(
              ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                  ->una_s32)) +
          1;
      sectcnt++;

      if (rva % 0x1000)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: FSG: Original section %d is misaligned\n",
                  sectcnt);

      if (rva < peinfo->sections[i].rva ||
          rva - peinfo->sections[i].rva >= peinfo->sections[i].vsz) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: FSG: Original section %d is out of bounds\n",
                  sectcnt);
        break;
      }
    }

    if (t >= gp - 4 || (((const union unaligned_32 *)(support + t))->una_s32)) {
      break;
    }

    if ((sections = (struct cli_exe_section *)cli_malloc(
             (sectcnt + 1) * sizeof(struct cli_exe_section))) == ((void *)0)) {
      cli_errmsg(
          "cli_scanpe: FSG: Unable to allocate memory for sections %llu\n",
          (long long unsigned)((sectcnt + 1) * sizeof(struct cli_exe_section)));
      cli_exe_info_destroy(peinfo);
      return CL_EMEM;
    }

    sections[0].rva = newedi;
    for (t = 1; t <= (uint32_t)sectcnt; t++)
      sections[t].rva =
          (((const union unaligned_32 *)(support + 8 + t * 4))->una_s32) - 1 -
          ((uint32_t)(
              ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                  ->una_s32));

    if (!peinfo->sections[i + 1].rsz ||
        !(src = fmap_need_off_once(map, peinfo->sections[i + 1].raw, ssize))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: Can't read raw data of section %d\n", i);
      cli_exe_info_destroy(peinfo);
      free(sections);
      return CL_EREAD;
    }

    if ((dest = (char *)cli_calloc(dsize, sizeof(char))) == ((void *)0)) {
      cli_exe_info_destroy(peinfo);
      free(sections);
      return CL_EMEM;
    }

    oldep = peinfo->vep + 161 + 6 +
            (((const union unaligned_32 *)(epbuff + 163))->una_s32);
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_scanpe: FSG: found old EP @%x\n", oldep);

    if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
      cli_exe_info_destroy(peinfo);
      cli_multifree(dest, sections, 0);
      return CL_EMEM;
    }
    if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG"
                                ": Can't create file %s\n",
                                tempfile);
      free(tempfile);
      cli_exe_info_destroy(peinfo);
      cli_multifree(dest, sections, 0);
      return CL_ECREAT;
    };
    switch ((unfsg_133(
        src + newesi - peinfo->sections[i + 1].rva, dest,
        ssize + peinfo->sections[i + 1].rva - newesi, dsize, sections, sectcnt,
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32)),
        oldep, ndesc))) {
    case 1:
      if (ctx->engine->keeptmp)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: FSG"
                  ": Unpacked and rebuilt executable saved in %s\n",
                  tempfile);
      else
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: FSG"
                                  ": Unpacked and rebuilt executable\n");
      cli_multifree(dest, sections, 0);
      cli_exe_info_destroy(peinfo);
      lseek(ndesc, 0, 0);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
      do {
      } while (0);
      if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) == CL_VIRUS) {
        close(ndesc);
        do {
        } while (0);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_VIRUS;
      }
      do {
      } while (0);
      close(ndesc);
      if (!ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
          free(tempfile);
          return CL_EUNLINK;
        }
      };
      free(tempfile);
      return CL_CLEAN;
    case 0:
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG"
                                ": Successfully decompressed\n");
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        free(sections);
        return CL_EUNLINK;
      }
      free(tempfile);
      free(sections);
      found = 0;
      upx_success = 1;
      break;
      ;
    default:
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG"
                                ": Unpacking failed\n");
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        cli_multifree(dest, sections, 0);
        return CL_EUNLINK;
      }
      cli_multifree(dest, sections, 0);
      free(tempfile);
    };
    break;
  }

  while (found && (ctx->dconf->pe & 0x40) && epbuff[0] == '\xbb' &&
         (((const union unaligned_32 *)(epbuff + 1))->una_s32) -
                 ((uint32_t)(((const union unaligned_32 *)(&(
                                  peinfo->pe_opt.opt32.ImageBase)))
                                 ->una_s32)) <
             peinfo->min &&
         epbuff[5] == '\xbf' && epbuff[10] == '\xbe' &&
         peinfo->vep >= peinfo->sections[i + 1].rva &&
         peinfo->vep - peinfo->sections[i + 1].rva >
             peinfo->sections[i + 1].rva - 0xe0) {
    int sectcnt = 0;
    uint32_t gp,
        t = cli_rawaddr((((const union unaligned_32 *)(epbuff + 1))->una_s32) -
                            ((uint32_t)(((const union unaligned_32 *)(&(
                                             peinfo->pe_opt.opt32.ImageBase)))
                                            ->una_s32)),
                        ((void *)0), 0, &err, fsize, peinfo->hdr_size);
    const char *support;
    uint32_t newesi =
        (((const union unaligned_32 *)(epbuff + 11))->una_s32) -
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32));
    uint32_t newedi =
        (((const union unaligned_32 *)(epbuff + 6))->una_s32) -
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32));
    uint32_t oldep = peinfo->vep - peinfo->sections[i + 1].rva;
    struct cli_exe_section *sections;

    ssize = peinfo->sections[i + 1].rsz;
    dsize = peinfo->sections[i].vsz;

    if (err) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Support data out of padding area\n");
      break;
    }

    if (newesi < peinfo->sections[i + 1].rva ||
        newesi - peinfo->sections[i + 1].rva >= peinfo->sections[i + 1].raw) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Source buffer out of section bounds\n");
      break;
    }

    if (newedi != peinfo->sections[i].rva) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Bad destination (is %x should be %x)\n",
                newedi, peinfo->sections[i].rva);
      break;
    }

    if (cli_checklimits("cli_scanpe: FSG", ctx,
                        (((dsize) > (ssize) ? (dsize) : (ssize))), 0,
                        0) != CL_CLEAN) {
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    };

    if (ssize <= 0x19 || dsize <= ssize) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Size mismatch (ssize: %d, dsize: %d)\n",
                ssize, dsize);
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    }

    gp = peinfo->sections[i + 1].raw - t;

    if (cli_checklimits("cli_scanpe: FSG", ctx, (gp), 0, 0) != CL_CLEAN) {
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    }

    if (!(support = fmap_need_off_once(map, t, gp))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: Can't read %d bytes from padding area\n", gp);
      cli_exe_info_destroy(peinfo);
      return CL_EREAD;
    }

    for (t = 0; t < gp - 2; t += 2) {
      uint32_t rva = support[t] | (support[t + 1] << 8);

      if (rva == 2 || rva == 1)
        break;

      rva =
          ((rva - 2) << 12) -
          ((uint32_t)(
              ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                  ->una_s32));
      sectcnt++;

      if (rva < peinfo->sections[i].rva ||
          rva - peinfo->sections[i].rva >= peinfo->sections[i].vsz) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: FSG: Original section %d is out of bounds\n",
                  sectcnt);
        break;
      }
    }

    if (t >= gp - 10 ||
        (((const union unaligned_32 *)(support + t + 6))->una_s32) != 2)
      break;

    if ((sections = (struct cli_exe_section *)cli_malloc(
             (sectcnt + 1) * sizeof(struct cli_exe_section))) == ((void *)0)) {
      cli_errmsg(
          "cli_scanpe: FSG: Unable to allocate memory for sections %llu\n",
          (long long unsigned)((sectcnt + 1) * sizeof(struct cli_exe_section)));
      cli_exe_info_destroy(peinfo);
      return CL_EMEM;
    }

    sections[0].rva = newedi;
    for (t = 0; t <= (uint32_t)sectcnt - 1; t++)
      sections[t + 1].rva =
          (((support[t * 2] | (support[t * 2 + 1] << 8)) - 2) << 12) -
          ((uint32_t)(
              ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                  ->una_s32));

    if (!peinfo->sections[i + 1].rsz ||
        !(src = fmap_need_off_once(map, peinfo->sections[i + 1].raw, ssize))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: FSG: Can't read raw data of section %d\n", i);
      cli_exe_info_destroy(peinfo);
      free(sections);
      return CL_EREAD;
    }

    if ((dest = (char *)cli_calloc(dsize, sizeof(char))) == ((void *)0)) {
      cli_exe_info_destroy(peinfo);
      free(sections);
      return CL_EMEM;
    }

    gp = 0xda + 6 * (epbuff[16] == '\xe8');
    oldep = peinfo->vep + gp + 6 +
            (((const union unaligned_32 *)(src + gp + 2 + oldep))->una_s32);
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_scanpe: FSG: found old EP @%x\n", oldep);

    if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
      cli_exe_info_destroy(peinfo);
      cli_multifree(dest, sections, 0);
      return CL_EMEM;
    }
    if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG"
                                ": Can't create file %s\n",
                                tempfile);
      free(tempfile);
      cli_exe_info_destroy(peinfo);
      cli_multifree(dest, sections, 0);
      return CL_ECREAT;
    };
    switch ((unfsg_133(
        src + newesi - peinfo->sections[i + 1].rva, dest,
        ssize + peinfo->sections[i + 1].rva - newesi, dsize, sections, sectcnt,
        ((uint32_t)(
            ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                ->una_s32)),
        oldep, ndesc))) {
    case 1:
      if (ctx->engine->keeptmp)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: FSG"
                  ": Unpacked and rebuilt executable saved in %s\n",
                  tempfile);
      else
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: FSG"
                                  ": Unpacked and rebuilt executable\n");
      cli_multifree(dest, sections, 0);
      cli_exe_info_destroy(peinfo);
      lseek(ndesc, 0, 0);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
      do {
      } while (0);
      if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) == CL_VIRUS) {
        close(ndesc);
        do {
        } while (0);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_VIRUS;
      }
      do {
      } while (0);
      close(ndesc);
      if (!ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
          free(tempfile);
          return CL_EUNLINK;
        }
      };
      free(tempfile);
      return CL_CLEAN;
    case 0:
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG"
                                ": Successfully decompressed\n");
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        free(sections);
        return CL_EUNLINK;
      }
      free(tempfile);
      free(sections);
      found = 0;
      upx_success = 1;
      break;
      ;
    default:
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: FSG"
                                ": Unpacking failed\n");
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        cli_multifree(dest, sections, 0);
        return CL_EUNLINK;
      }
      cli_multifree(dest, sections, 0);
      free(tempfile);
    };

    break;
  }

  if (found && (ctx->dconf->pe & 0x20)) {
    ssize = peinfo->sections[i + 1].rsz;
    dsize = peinfo->sections[i].vsz + peinfo->sections[i + 1].vsz;
    if (cli_checklimits("cli_scanpe: UPX", ctx,
                        (((dsize) > (ssize) ? (dsize) : (ssize))), 0,
                        0) != CL_CLEAN) {
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    };

    if (ssize <= 0x19 || dsize <= ssize || dsize > (182 * 1024 * 1024)) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: UPX: Size mismatch or dsize too "
                                "big (ssize: %d, dsize: %d)\n",
                                ssize, dsize);
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    }

    if (!peinfo->sections[i + 1].rsz ||
        !(src = fmap_need_off_once(map, peinfo->sections[i + 1].raw, ssize))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: UPX: Can't read raw data of section %d\n", i + 1);
      cli_exe_info_destroy(peinfo);
      return CL_EREAD;
    }

    if ((dest = (char *)cli_calloc(dsize + 8192, sizeof(char))) ==
        ((void *)0)) {
      cli_exe_info_destroy(peinfo);
      return CL_EMEM;
    }

    if (cli_memstr("\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11"
                   "\xdb\x11\xc9\x11\xc9\x75\x20\x41\x01\xdb",
                   24, epbuff + 0x69, 13) ||
        cli_memstr("\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11"
                   "\xdb\x11\xc9\x11\xc9\x75\x20\x41\x01\xdb",
                   24, epbuff + 0x69 + 8, 13)) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: UPX: Looks like a NRV2B decompression routine\n");
      upxfn = upx_inflate2b;
    } else if (cli_memstr("\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb"
                          "\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9",
                          24, epbuff + 0x69, 13) ||
               cli_memstr("\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb"
                          "\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9",
                          24, epbuff + 0x69 + 8, 13)) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: UPX: Looks like a NRV2D decompression routine\n");
      upxfn = upx_inflate2d;
    } else if (cli_memstr("\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a"
                          "\x06\x46\x83\xf0\xff\x74\x75\xd1\xf8\x89\xc5",
                          24, epbuff + 0x69, 13) ||
               cli_memstr("\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a"
                          "\x06\x46\x83\xf0\xff\x74\x75\xd1\xf8\x89\xc5",
                          24, epbuff + 0x69 + 8, 13)) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: UPX: Looks like a NRV2E decompression routine\n");
      upxfn = upx_inflate2e;
    }

    if (upxfn) {
      int skew =
          (((const union unaligned_32 *)(epbuff + 2))->una_s32) -
          ((uint32_t)(
              ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                  ->una_s32)) -
          peinfo->sections[i + 1].rva;

      if (epbuff[1] != '\xbe' || skew <= 0 || skew > 0xfff) {

        skew = 0;
      } else if ((unsigned int)skew > ssize) {

        skew = 0;
      } else {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: UPX: UPX1 seems skewed by %d bytes\n", skew);
      }

      if (upxfn(src + skew, ssize - skew, dest, &dsize, peinfo->sections[i].rva,
                peinfo->sections[i + 1].rva, peinfo->vep - skew) >= 0) {
        upx_success = 1;
      }

      else if (skew && (upxfn(src, ssize, dest, &dsize, peinfo->sections[i].rva,
                              peinfo->sections[i + 1].rva, peinfo->vep) >= 0)) {
        upx_success = 1;
      }

      if (upx_success)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: UPX: Successfully decompressed\n");
      else
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: UPX: Preferred decompressor failed\n");
    }

    if (!upx_success && upxfn != upx_inflate2b) {
      if (upx_inflate2b(src, ssize, dest, &dsize, peinfo->sections[i].rva,
                        peinfo->sections[i + 1].rva, peinfo->vep) == -1 &&
          upx_inflate2b(src + 0x15, ssize - 0x15, dest, &dsize,
                        peinfo->sections[i].rva, peinfo->sections[i + 1].rva,
                        peinfo->vep - 0x15) == -1) {

        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: UPX: NRV2B decompressor failed\n");
      } else {
        upx_success = 1;
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: UPX: Successfully decompressed with NRV2B\n");
      }
    }

    if (!upx_success && upxfn != upx_inflate2d) {
      if (upx_inflate2d(src, ssize, dest, &dsize, peinfo->sections[i].rva,
                        peinfo->sections[i + 1].rva, peinfo->vep) == -1 &&
          upx_inflate2d(src + 0x15, ssize - 0x15, dest, &dsize,
                        peinfo->sections[i].rva, peinfo->sections[i + 1].rva,
                        peinfo->vep - 0x15) == -1) {

        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: UPX: NRV2D decompressor failed\n");
      } else {
        upx_success = 1;
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: UPX: Successfully decompressed with NRV2D\n");
      }
    }

    if (!upx_success && upxfn != upx_inflate2e) {
      if (upx_inflate2e(src, ssize, dest, &dsize, peinfo->sections[i].rva,
                        peinfo->sections[i + 1].rva, peinfo->vep) == -1 &&
          upx_inflate2e(src + 0x15, ssize - 0x15, dest, &dsize,
                        peinfo->sections[i].rva, peinfo->sections[i + 1].rva,
                        peinfo->vep - 0x15) == -1) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: UPX: NRV2E decompressor failed\n");
      } else {
        upx_success = 1;
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: UPX: Successfully decompressed with NRV2E\n");
      }
    }

    if (cli_memstr("\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90\x90"
                   "\x90\x90\x90\x55\x57\x56",
                   20, epbuff + 0x2f, 20)) {
      uint32_t strictdsize =
                   (((const union unaligned_32 *)(epbuff + 0x21))->una_s32),
               skew = 0;
      if (ssize > 0x15 && epbuff[0] == '\x60' && epbuff[1] == '\xbe') {

        skew = (((const union unaligned_32 *)(epbuff + 2))->una_s32) -
               peinfo->sections[i + 1].rva - peinfo->pe_opt.opt32.ImageBase;
        if (skew != 0x15)
          skew = 0;
      }

      if (strictdsize <= dsize)
        upx_success = upx_inflatelzma(src + skew, ssize - skew, dest,
                                      &strictdsize, peinfo->sections[i].rva,
                                      peinfo->sections[i + 1].rva, peinfo->vep,
                                      0x20003) >= 0;
    } else if (cli_memstr("\x56\x83\xc3\x04\x53\x50\xc7\x03", 8, epbuff + 0x39,
                          8) &&
               cli_memstr("\x90\x90\x90\x55\x57\x56\x53\x83", 8, epbuff + 0x45,
                          8)) {
      uint32_t strictdsize =
                   (((const union unaligned_32 *)(epbuff + 0x2b))->una_s32),
               skew = 0;
      uint32_t properties =
          (((const union unaligned_32 *)(epbuff + 0x41))->una_s32);
      if (ssize > 0x15 && epbuff[0] == '\x60' && epbuff[1] == '\xbe') {

        skew = (((const union unaligned_32 *)(epbuff + 2))->una_s32) -
               peinfo->sections[i + 1].rva - peinfo->pe_opt.opt32.ImageBase;
        if (skew != 0x15)
          skew = 0;
      }

      if (strictdsize <= dsize)
        upx_success = upx_inflatelzma(src + skew, ssize - skew, dest,
                                      &strictdsize, peinfo->sections[i].rva,
                                      peinfo->sections[i + 1].rva, peinfo->vep,
                                      properties) >= 0;
    }

    if (!upx_success) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: UPX: All decompressors failed\n");
      free(dest);
    }
  }

  if (upx_success) {
    cli_exe_info_destroy(peinfo);

    if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
      cli_exe_info_destroy(peinfo);
      cli_multifree(dest, 0);
      return CL_EMEM;
    }
    if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: UPX/FSG"
                                ": Can't create file %s\n",
                                tempfile);
      free(tempfile);
      cli_exe_info_destroy(peinfo);
      cli_multifree(dest, 0);
      return CL_ECREAT;
    };

    if ((unsigned int)write(ndesc, dest, dsize) != dsize) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: UPX/FSG: Can't write %d bytes\n",
                                dsize);
      free(tempfile);
      free(dest);
      close(ndesc);
      return CL_EWRITE;
    }

    free(dest);
    if (lseek(ndesc, 0, 0) == -1) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: UPX/FSG: lseek() failed\n");
      close(ndesc);
      do {
      } while (0);
      if (!ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
          free(tempfile);
          return CL_EUNLINK;
        }
      };
      free(tempfile);
      return CL_ESEEK;
    }

    if (ctx->engine->keeptmp)
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: UPX/FSG: Decompressed data saved in %s\n",
                tempfile);

    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("***** Scanning decompressed file *****\n");
    do {
    } while (0);
    if ((ret = cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0))) ==
        CL_VIRUS) {
      close(ndesc);
      do {
      } while (0);
      if (!ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
          free(tempfile);
          return CL_EUNLINK;
        }
      };
      free(tempfile);
      return CL_VIRUS;
    }

    do {
    } while (0);
    close(ndesc);
    if (!ctx->engine->keeptmp) {
      if (cli_unlink(tempfile)) {
        free(tempfile);
        return CL_EUNLINK;
      }
    };
    free(tempfile);
    return ret;
  }

  if (epsize < 200) {
    cli_exe_info_destroy(peinfo);
    return CL_CLEAN;
  }

  found = 2;

  if (epbuff[0] != '\xb8' ||
      (uint32_t)(((const union unaligned_32 *)(epbuff + 1))->una_s32) !=
          peinfo->sections[peinfo->nsections - 1].rva +
              ((uint32_t)(((const union unaligned_32 *)(&(
                               peinfo->pe_opt.opt32.ImageBase)))
                              ->una_s32))) {
    if (peinfo->nsections < 2 || epbuff[0] != '\xb8' ||
        (uint32_t)(((const union unaligned_32 *)(epbuff + 1))->una_s32) !=
            peinfo->sections[peinfo->nsections - 2].rva +
                ((uint32_t)(((const union unaligned_32 *)(&(
                                 peinfo->pe_opt.opt32.ImageBase)))
                                ->una_s32)))
      found = 0;
    else
      found = 1;
  }

  if (found && (ctx->dconf->pe & 0x100)) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_scanpe: Petite: v2.%d compression detected\n", found);

    if ((((const union unaligned_32 *)(epbuff + 0x80))->una_s32) ==
        0x163c988d) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: Petite: level zero compression is "
                                "not supported yet\n");
    } else {
      dsize = peinfo->max - peinfo->min;

      if (cli_checklimits("cli_scanpe: Petite", ctx, (dsize), 0, 0) !=
          CL_CLEAN) {
        cli_exe_info_destroy(peinfo);
        return CL_CLEAN;
      };

      if ((dest = (char *)cli_calloc(dsize, sizeof(char))) == ((void *)0)) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: Petite: Can't allocate %d bytes\n", dsize);
        cli_exe_info_destroy(peinfo);
        return CL_EMEM;
      }

      for (i = 0; i < peinfo->nsections; i++) {
        if (peinfo->sections[i].raw) {
          unsigned int r_ret;

          if (!peinfo->sections[i].rsz)
            goto out_no_petite;

          if (!((size_t)(dsize) > 0 && (size_t)(peinfo->sections[i].ursz) > 0 &&
                (size_t)(peinfo->sections[i].ursz) <= (size_t)(dsize) &&
                (ptrdiff_t)(dest + peinfo->sections[i].rva - peinfo->min) >=
                    (ptrdiff_t)(dest) &&
                (ptrdiff_t)(dest + peinfo->sections[i].rva - peinfo->min) +
                        (ptrdiff_t)(peinfo->sections[i].ursz) <=
                    (ptrdiff_t)(dest) + (ptrdiff_t)(dsize) &&
                (ptrdiff_t)(dest + peinfo->sections[i].rva - peinfo->min) +
                        (ptrdiff_t)(peinfo->sections[i].ursz) >
                    (ptrdiff_t)(dest) &&
                (ptrdiff_t)(dest + peinfo->sections[i].rva - peinfo->min) <
                    (ptrdiff_t)(dest) + (ptrdiff_t)(dsize))

          )
            goto out_no_petite;

          r_ret = fmap_readn(map, dest + peinfo->sections[i].rva - peinfo->min,
                             peinfo->sections[i].raw, peinfo->sections[i].ursz);
          if (r_ret != peinfo->sections[i].ursz) {
          out_no_petite:
            cli_exe_info_destroy(peinfo);
            free(dest);
            return CL_CLEAN;
          }
        }
      }

      if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
        cli_exe_info_destroy(peinfo);
        cli_multifree(dest, 0);
        return CL_EMEM;
      }
      if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: Petite"
                                  ": Can't create file %s\n",
                                  tempfile);
        free(tempfile);
        cli_exe_info_destroy(peinfo);
        cli_multifree(dest, 0);
        return CL_ECREAT;
      };
      switch ((petite_inflate2x_1to9(
          dest, peinfo->min, peinfo->max - peinfo->min, peinfo->sections,
          peinfo->nsections - (found == 1 ? 1 : 0),
          ((uint32_t)(
              ((const union unaligned_32 *)(&(peinfo->pe_opt.opt32.ImageBase)))
                  ->una_s32)),
          peinfo->vep, ndesc, found,
          ((uint32_t)(
              ((const union unaligned_32 *)(&(peinfo->dirs[2].VirtualAddress)))
                  ->una_s32)),
          ((uint32_t)(((const union unaligned_32 *)(&(peinfo->dirs[2].Size)))
                          ->una_s32))))) {
      case 0:
        if (ctx->engine->keeptmp)
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal(
                    "Petite"
                    ": Unpacked and rebuilt executable saved in %s\n",
                    tempfile);
        else
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("Petite"
                                    ": Unpacked and rebuilt executable\n");
        cli_multifree(dest, 0);
        cli_exe_info_destroy(peinfo);
        lseek(ndesc, 0, 0);
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
        do {
        } while (0);
        if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) ==
            CL_VIRUS) {
          close(ndesc);
          do {
          } while (0);
          if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile)) {
              free(tempfile);
              return CL_EUNLINK;
            }
          };
          free(tempfile);
          return CL_VIRUS;
        }
        do {
        } while (0);
        close(ndesc);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_CLEAN;
        (void)0;
      default:
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("Petite"
                                  ": Unpacking failed\n");
        close(ndesc);
        if (cli_unlink(tempfile)) {
          cli_exe_info_destroy(peinfo);
          free(tempfile);
          cli_multifree(dest, 0);
          return CL_EUNLINK;
        }
        cli_multifree(dest, 0);
        free(tempfile);
      };
    }
  }

  if ((ctx->dconf->pe & 0x200) && peinfo->nsections > 1 &&
      peinfo->vep >= peinfo->sections[peinfo->nsections - 1].rva &&
      0x3217 - 4 <= peinfo->sections[peinfo->nsections - 1].rva +
                        peinfo->sections[peinfo->nsections - 1].rsz &&
      peinfo->vep < peinfo->sections[peinfo->nsections - 1].rva +
                        peinfo->sections[peinfo->nsections - 1].rsz - 0x3217 -
                        4 &&
      memcmp(epbuff + 4, "\xe8\x00\x00\x00\x00\x8b\x1c\x24\x83\xc3", 10) == 0) {

    char *spinned;

    if (cli_checklimits("cli_scanpe: PEspin", ctx, (fsize), 0, 0) != CL_CLEAN) {
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    };

    if ((spinned = (char *)cli_malloc(fsize)) == ((void *)0)) {
      cli_errmsg(
          "cli_scanpe: PESping: Unable to allocate memory for spinned %lu\n",
          (unsigned long)fsize);
      cli_exe_info_destroy(peinfo);
      return CL_EMEM;
    }

    if (fmap_readn(map, spinned, 0, fsize) != fsize) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: PESpin: Can't read %lu bytes\n",
                                (unsigned long)fsize);
      free(spinned);
      cli_exe_info_destroy(peinfo);
      return CL_EREAD;
    }

    if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
      cli_exe_info_destroy(peinfo);
      cli_multifree(spinned, 0);
      return CL_EMEM;
    }
    if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: PESpin"
                                ": Can't create file %s\n",
                                tempfile);
      free(tempfile);
      cli_exe_info_destroy(peinfo);
      cli_multifree(spinned, 0);
      return CL_ECREAT;
    };
    switch ((unspin(spinned, fsize, peinfo->sections, peinfo->nsections - 1,
                    peinfo->vep, ndesc, ctx))) {
    case 0:
      if (ctx->engine->keeptmp)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: PEspin"
                  ": Unpacked and rebuilt executable saved in %s\n",
                  tempfile);
      else
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: PEspin"
                                  ": Unpacked and rebuilt executable\n");
      cli_multifree(spinned, 0);
      cli_exe_info_destroy(peinfo);
      lseek(ndesc, 0, 0);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
      do {
      } while (0);
      if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) == CL_VIRUS) {
        close(ndesc);
        do {
        } while (0);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_VIRUS;
      }
      do {
      } while (0);
      close(ndesc);
      if (!ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
          free(tempfile);
          return CL_EUNLINK;
        }
      };
      free(tempfile);
      return CL_CLEAN;
    case 2:
      free(spinned);
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        return CL_EUNLINK;
      }
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: PESpin: Size exceeded\n");
      free(tempfile);
      break;
      ;
    default:
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: PEspin"
                                ": Unpacking failed\n");
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        cli_multifree(spinned, 0);
        return CL_EUNLINK;
      }
      cli_multifree(spinned, 0);
      free(tempfile);
    };
  }

  if ((ctx->dconf->pe & 0x400) && peinfo->nsections > 1 &&
      (((uint32_t)(((const union unaligned_32 *)(&(
                        peinfo->pe_opt.opt32.AddressOfEntryPoint)))
                       ->una_s32)) ==
       peinfo->sections[peinfo->nsections - 1].rva + 0x60)) {

    uint32_t ecx = 0;
    int16_t offset;

    if (!memcmp(epbuff,
                "\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED",
                15) &&
        !memcmp(epbuff + 0x26,
                "\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC", 13) &&
        ((uint8_t)epbuff[0x13] == 0xB9) &&
        ((uint16_t)((((const union unaligned_16 *)(epbuff + 0x18))->una_s16)) ==
         0xE981) &&
        !memcmp(epbuff + 0x1e, "\x8B\xD5\x81\xC2", 4)) {

      offset = 0;
      if (0x6c - (((const union unaligned_32 *)(epbuff + 0xf))->una_s32) +
              (((const union unaligned_32 *)(epbuff + 0x22))->una_s32) ==
          0xC6)
        ecx = (((const union unaligned_32 *)(epbuff + 0x14))->una_s32) -
              (((const union unaligned_32 *)(epbuff + 0x1a))->una_s32);
    }

    if (!ecx && !memcmp(epbuff, "\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57", 9) &&
        !memcmp(epbuff + 0x17, "\xe8\x00\x00\x00\x00\x5d\x81\xed", 8) &&
        ((uint8_t)epbuff[0x23] == 0xB9)) {

      offset = 0x10;
      if (0x6c - (((const union unaligned_32 *)(epbuff + 0x1f))->una_s32) +
              (((const union unaligned_32 *)(epbuff + 0x32))->una_s32) ==
          0xC6)
        ecx = (((const union unaligned_32 *)(epbuff + 0x24))->una_s32) -
              (((const union unaligned_32 *)(epbuff + 0x2a))->una_s32);
    }

    if (!ecx && !memcmp(epbuff, "\x60\xe8\x00\x00\x00\x00\x5d\x81\xed", 9) &&
        ((uint8_t)epbuff[0xd] == 0xb9) &&
        ((uint16_t)(((const union unaligned_16 *)(epbuff + 0x12))->una_s16) ==
         0xbd8d) &&
        !memcmp(epbuff + 0x18, "\x8b\xf7\xac", 3)) {

      offset = -0x18;
      if (0x66 - (((const union unaligned_32 *)(epbuff + 0x9))->una_s32) +
              (((const union unaligned_32 *)(epbuff + 0x14))->una_s32) ==
          0xae)
        ecx = (((const union unaligned_32 *)(epbuff + 0xe))->una_s32);
    }

    if (ecx > 0x800 && ecx < 0x2000 &&
        !memcmp(epbuff + 0x63 + offset, "\xaa\xe2\xcc", 3) &&
        (fsize >=
         peinfo->sections[peinfo->nsections - 1].raw + 0xC6 + ecx + offset)) {

      char *spinned;

      if ((spinned = (char *)cli_malloc(fsize)) == ((void *)0)) {
        cli_errmsg(
            "cli_scanpe: yC: Unable to allocate memory for spinned %lu\n",
            (unsigned long)fsize);
        cli_exe_info_destroy(peinfo);
        return CL_EMEM;
      }

      if (fmap_readn(map, spinned, 0, fsize) != fsize) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: yC: Can't read %lu bytes\n",
                                  (unsigned long)fsize);
        free(spinned);
        cli_exe_info_destroy(peinfo);
        return CL_EREAD;
      }

      do {
        unsigned int yc_unp_num_viruses = ctx->num_viruses;
        const char *yc_unp_virname = ((void *)0);

        if (ctx->virname)
          yc_unp_virname = ctx->virname[0];

        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("%d,%d,%d,%d\n", peinfo->nsections - 1,
                                  peinfo->e_lfanew, ecx, offset);
        if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
          cli_exe_info_destroy(peinfo);
          cli_multifree(spinned, 0);
          return CL_EMEM;
        }
        if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("cli_scanpe: yC"
                                    ": Can't create file %s\n",
                                    tempfile);
          free(tempfile);
          cli_exe_info_destroy(peinfo);
          cli_multifree(spinned, 0);
          return CL_ECREAT;
        };
        switch ((yc_decrypt(ctx, spinned, fsize, peinfo->sections,
                            peinfo->nsections - 1, peinfo->e_lfanew, ndesc, ecx,
                            offset))) {
        case 0:
          if (ctx->engine->keeptmp)
            (!__builtin_expect(!!(cli_debug_flag), 0))
                ? (void)0
                : cli_dbgmsg_internal(
                      "cli_scanpe: yC"
                      ": Unpacked and rebuilt executable saved in %s\n",
                      tempfile);
          else
            (!__builtin_expect(!!(cli_debug_flag), 0))
                ? (void)0
                : cli_dbgmsg_internal("cli_scanpe: yC"
                                      ": Unpacked and rebuilt executable\n");
          cli_multifree(spinned, 0);
          cli_exe_info_destroy(peinfo);
          lseek(ndesc, 0, 0);
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
          do {
          } while (0);
          if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) ==
              CL_VIRUS) {
            close(ndesc);
            do {
            } while (0);
            if (!ctx->engine->keeptmp) {
              if (cli_unlink(tempfile)) {
                free(tempfile);
                return CL_EUNLINK;
              }
            };
            free(tempfile);
            return CL_VIRUS;
          }
          do {
          } while (0);
          close(ndesc);
          if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile)) {
              free(tempfile);
              return CL_EUNLINK;
            }
          };
          free(tempfile);
          return CL_CLEAN;
          (void)0;
        default:
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("cli_scanpe: yC"
                                    ": Unpacking failed\n");
          close(ndesc);
          if (cli_unlink(tempfile)) {
            cli_exe_info_destroy(peinfo);
            free(tempfile);
            cli_multifree(spinned, 0);
            return CL_EUNLINK;
          }
          cli_multifree(spinned, 0);
          free(tempfile);
        };

        if ((ctx->options->general & 0x1) &&
            yc_unp_num_viruses != ctx->num_viruses) {
          cli_exe_info_destroy(peinfo);
          return CL_VIRUS;
        } else if (ctx->virname && yc_unp_virname != ctx->virname[0]) {
          cli_exe_info_destroy(peinfo);
          return CL_VIRUS;
        }
      } while (0);
    }
  }

  while ((ctx->dconf->pe & 0x800) && peinfo->nsections > 1 &&
         peinfo->vep == peinfo->sections[peinfo->nsections - 1].rva &&
         memcmp(epbuff, "\x53\x55\x8b\xe8\x33\xdb\xeb", 7) == 0 &&
         memcmp(epbuff + 0x68,
                "\xe8\x00\x00\x00\x00\x58\x2d\x6d\x00\x00\x00\x50\x60\x33\xc9"
                "\x50\x58\x50\x50",
                19) == 0) {
    uint32_t head = peinfo->sections[peinfo->nsections - 1].raw;
    uint8_t *packer;
    char *src;

    ssize = 0;
    for (i = 0;; i++) {
      if (peinfo->sections[i].raw < head)
        head = peinfo->sections[i].raw;

      if (i + 1 == peinfo->nsections)
        break;

      if (ssize < peinfo->sections[i].rva + peinfo->sections[i].vsz)
        ssize = peinfo->sections[i].rva + peinfo->sections[i].vsz;
    }

    if (!head || !ssize || head > ssize)
      break;

    if (cli_checklimits("cli_scanpe: WWPack", ctx, (ssize), 0, 0) != CL_CLEAN) {
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    };

    if (!(src = (char *)cli_calloc(ssize, sizeof(char)))) {
      cli_exe_info_destroy(peinfo);
      return CL_EMEM;
    }

    if (fmap_readn(map, src, 0, head) != head) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: WWPack: Can't read %d bytes from headers\n", head);
      free(src);
      cli_exe_info_destroy(peinfo);
      return CL_EREAD;
    }

    for (i = 0; i < (unsigned int)peinfo->nsections - 1; i++) {
      if (!peinfo->sections[i].rsz)
        continue;

      if (!((size_t)(ssize) > 0 && (size_t)(peinfo->sections[i].rsz) > 0 &&
            (size_t)(peinfo->sections[i].rsz) <= (size_t)(ssize) &&
            (ptrdiff_t)(src + peinfo->sections[i].rva) >= (ptrdiff_t)(src) &&
            (ptrdiff_t)(src + peinfo->sections[i].rva) +
                    (ptrdiff_t)(peinfo->sections[i].rsz) <=
                (ptrdiff_t)(src) + (ptrdiff_t)(ssize) &&
            (ptrdiff_t)(src + peinfo->sections[i].rva) +
                    (ptrdiff_t)(peinfo->sections[i].rsz) >
                (ptrdiff_t)(src) &&
            (ptrdiff_t)(src + peinfo->sections[i].rva) <
                (ptrdiff_t)(src) + (ptrdiff_t)(ssize)))
        break;

      if (fmap_readn(map, src + peinfo->sections[i].rva,
                     peinfo->sections[i].raw,
                     peinfo->sections[i].rsz) != peinfo->sections[i].rsz)
        break;
    }

    if (i + 1 != peinfo->nsections) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: WWpack: Probably hacked/damaged file.\n");
      free(src);
      break;
    }

    if ((packer =
             (uint8_t *)cli_calloc(peinfo->sections[peinfo->nsections - 1].rsz,
                                   sizeof(char))) == ((void *)0)) {
      free(src);
      cli_exe_info_destroy(peinfo);
      return CL_EMEM;
    }

    if (!peinfo->sections[peinfo->nsections - 1].rsz ||
        fmap_readn(map, packer, peinfo->sections[peinfo->nsections - 1].raw,
                   peinfo->sections[peinfo->nsections - 1].rsz) !=
            peinfo->sections[peinfo->nsections - 1].rsz) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: WWPack: Can't read %d bytes from wwpack sect\n",
                peinfo->sections[peinfo->nsections - 1].rsz);
      free(src);
      free(packer);
      cli_exe_info_destroy(peinfo);
      return CL_EREAD;
    }

    if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
      cli_exe_info_destroy(peinfo);
      cli_multifree(src, packer, 0);
      return CL_EMEM;
    }
    if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: WWPack"
                                ": Can't create file %s\n",
                                tempfile);
      free(tempfile);
      cli_exe_info_destroy(peinfo);
      cli_multifree(src, packer, 0);
      return CL_ECREAT;
    };
    switch ((wwunpack((uint8_t *)src, ssize, packer, peinfo->sections,
                      peinfo->nsections - 1, peinfo->e_lfanew, ndesc))) {
    case 0:
      if (ctx->engine->keeptmp)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: WWPack"
                  ": Unpacked and rebuilt executable saved in %s\n",
                  tempfile);
      else
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: WWPack"
                                  ": Unpacked and rebuilt executable\n");
      cli_multifree(src, packer, 0);
      cli_exe_info_destroy(peinfo);
      lseek(ndesc, 0, 0);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
      do {
      } while (0);
      if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) == CL_VIRUS) {
        close(ndesc);
        do {
        } while (0);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_VIRUS;
      }
      do {
      } while (0);
      close(ndesc);
      if (!ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
          free(tempfile);
          return CL_EUNLINK;
        }
      };
      free(tempfile);
      return CL_CLEAN;
      (void)0;
    default:
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: WWPack"
                                ": Unpacking failed\n");
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        cli_multifree(src, packer, 0);
        return CL_EUNLINK;
      }
      cli_multifree(src, packer, 0);
      free(tempfile);
    };
    break;
  }

  while ((ctx->dconf->pe & 0x8000) &&
         ((peinfo->ep + (58 + 0x70e) < fsize) ||
          (peinfo->ep + (58 + 0x76a) < fsize) ||
          (peinfo->ep + (58 + 0x776) < fsize)) &&
         (!memcmp(epbuff, "\x60\xe8\x03\x00\x00\x00\xe9\xeb", 8))) {
    char *src;
    aspack_version_t aspack_ver = ASPACK_VER_NONE;

    if (epsize < 0x3bf)
      break;

    if (0 == memcmp(epbuff + (0x3b9), "\x68\x00\x00\x00\x00\xc3", 6)) {
      aspack_ver = ASPACK_VER_212;
    } else if (0 == memcmp(epbuff + (0x41f), "\x68\x00\x00\x00\x00\xc3", 6)) {
      aspack_ver = ASPACK_VER_OTHER;
    } else if (0 == memcmp(epbuff + (0x42B), "\x68\x00\x00\x00\x00\xc3", 6)) {
      aspack_ver = ASPACK_VER_242;
    } else {
      break;
    }
    ssize = 0;
    for (i = 0; i < peinfo->nsections; i++)
      if (ssize < peinfo->sections[i].rva + peinfo->sections[i].vsz)
        ssize = peinfo->sections[i].rva + peinfo->sections[i].vsz;

    if (!ssize)
      break;

    if (cli_checklimits("cli_scanpe: Aspack", ctx, (ssize), 0, 0) != CL_CLEAN) {
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    };

    if (!(src = (char *)cli_calloc(ssize, sizeof(char)))) {
      cli_exe_info_destroy(peinfo);
      return CL_EMEM;
    }
    for (i = 0; i < (unsigned int)peinfo->nsections; i++) {
      if (!peinfo->sections[i].rsz)
        continue;

      if (!((size_t)(ssize) > 0 && (size_t)(peinfo->sections[i].rsz) > 0 &&
            (size_t)(peinfo->sections[i].rsz) <= (size_t)(ssize) &&
            (ptrdiff_t)(src + peinfo->sections[i].rva) >= (ptrdiff_t)(src) &&
            (ptrdiff_t)(src + peinfo->sections[i].rva) +
                    (ptrdiff_t)(peinfo->sections[i].rsz) <=
                (ptrdiff_t)(src) + (ptrdiff_t)(ssize) &&
            (ptrdiff_t)(src + peinfo->sections[i].rva) +
                    (ptrdiff_t)(peinfo->sections[i].rsz) >
                (ptrdiff_t)(src) &&
            (ptrdiff_t)(src + peinfo->sections[i].rva) <
                (ptrdiff_t)(src) + (ptrdiff_t)(ssize)))
        break;

      if (fmap_readn(map, src + peinfo->sections[i].rva,
                     peinfo->sections[i].raw,
                     peinfo->sections[i].rsz) != peinfo->sections[i].rsz)
        break;
    }

    if (i != peinfo->nsections) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_scanpe: Aspack: Probably hacked/damaged Aspack file.\n");
      free(src);
      break;
    }

    if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
      cli_exe_info_destroy(peinfo);
      cli_multifree(src, 0);
      return CL_EMEM;
    }
    if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: Aspack"
                                ": Can't create file %s\n",
                                tempfile);
      free(tempfile);
      cli_exe_info_destroy(peinfo);
      cli_multifree(src, 0);
      return CL_ECREAT;
    };
    switch ((unaspack((uint8_t *)src, ssize, peinfo->sections,
                      peinfo->nsections, peinfo->vep - 1,
                      ((uint32_t)(((const union unaligned_32 *)(&(
                                       peinfo->pe_opt.opt32.ImageBase)))
                                      ->una_s32)),
                      ndesc, aspack_ver))) {
    case 1:
      if (ctx->engine->keeptmp)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: Aspack"
                  ": Unpacked and rebuilt executable saved in %s\n",
                  tempfile);
      else
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: Aspack"
                                  ": Unpacked and rebuilt executable\n");
      cli_multifree(src, 0);
      cli_exe_info_destroy(peinfo);
      lseek(ndesc, 0, 0);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
      do {
      } while (0);
      if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) == CL_VIRUS) {
        close(ndesc);
        do {
        } while (0);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_VIRUS;
      }
      do {
      } while (0);
      close(ndesc);
      if (!ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
          free(tempfile);
          return CL_EUNLINK;
        }
      };
      free(tempfile);
      return CL_CLEAN;
      (void)0;
    default:
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: Aspack"
                                ": Unpacking failed\n");
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        cli_multifree(src, 0);
        return CL_EUNLINK;
      }
      cli_multifree(src, 0);
      free(tempfile);
    };
    break;
  }

  while (ctx->dconf->pe & 0x1000) {
    uint32_t eprva = peinfo->vep;
    uint32_t start_of_stuff, rep = peinfo->ep;
    unsigned int nowinldr;
    const char *nbuff;

    src = epbuff;
    if (*epbuff == '\xe9') {
      eprva = (((const union unaligned_32 *)(epbuff + 1))->una_s32) +
              peinfo->vep + 5;
      if (!(rep = cli_rawaddr(eprva, peinfo->sections, peinfo->nsections, &err,
                              fsize, peinfo->hdr_size)) &&
          err)
        break;

      if (!(nbuff = fmap_need_off_once(map, rep, 24)))
        break;

      src = nbuff;
    }

    if (memcmp(src, "\x9c\x60\xe8\x00\x00\x00\x00\x5d\xb8\x07\x00\x00\x00", 13))
      break;

    nowinldr = 0x54 - (((const union unaligned_32 *)(src + 17))->una_s32);
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_scanpe: NsPack: Found *start_of_stuff @delta-%x\n",
              nowinldr);

    if (!(nbuff = fmap_need_off_once(map, rep - nowinldr, 4)))
      break;

    start_of_stuff = rep + (((const union unaligned_32 *)(nbuff))->una_s32);
    if (!(nbuff = fmap_need_off_once(map, start_of_stuff, 20)))
      break;

    src = nbuff;
    if (!(((const union unaligned_32 *)(nbuff))->una_s32)) {
      start_of_stuff += 4;
      src += 4;
    }

    ssize = (((const union unaligned_32 *)(src + 5))->una_s32) | 0xff;
    dsize = (((const union unaligned_32 *)(src + 9))->una_s32);

    if (cli_checklimits("cli_scanpe: NsPack", ctx,
                        (((ssize) > (dsize) ? (ssize) : (dsize))), 0,
                        0) != CL_CLEAN) {
      cli_exe_info_destroy(peinfo);
      return CL_CLEAN;
    };

    if (!ssize || !dsize || dsize != peinfo->sections[0].vsz)
      break;

    if (!(dest = cli_malloc(dsize))) {
      cli_errmsg("cli_scanpe: NsPack: Unable to allocate memory for dest %u\n",
                 dsize);
      break;
    }

    if (!(src = fmap_need_off(map, start_of_stuff, ssize))) {
      free(dest);
      break;
    }

    eprva += 0x27a;
    if (!(rep = cli_rawaddr(eprva, peinfo->sections, peinfo->nsections, &err,
                            fsize, peinfo->hdr_size)) &&
        err) {
      free(dest);
      break;
    }

    if (!(nbuff = fmap_need_off_once(map, rep, 5))) {
      free(dest);
      break;
    }

    fmap_unneed_off(map, start_of_stuff, ssize);
    eprva = eprva + 5 + (((const union unaligned_32 *)(nbuff + 1))->una_s32);
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_scanpe: NsPack: OEP = %08x\n", eprva);

    if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {
      cli_exe_info_destroy(peinfo);
      cli_multifree(dest, 0);
      return CL_EMEM;
    }
    if ((ndesc = open(tempfile, 02 | 0100 | 01000 | 0, 0400 | 0200)) < 0) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: NsPack"
                                ": Can't create file %s\n",
                                tempfile);
      free(tempfile);
      cli_exe_info_destroy(peinfo);
      cli_multifree(dest, 0);
      return CL_ECREAT;
    };
    switch ((unspack(src, dest, ctx, peinfo->sections[0].rva,
                     ((uint32_t)(((const union unaligned_32 *)(&(
                                      peinfo->pe_opt.opt32.ImageBase)))
                                     ->una_s32)),
                     eprva, ndesc))) {
    case 0:
      if (ctx->engine->keeptmp)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_scanpe: NsPack"
                  ": Unpacked and rebuilt executable saved in %s\n",
                  tempfile);
      else
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: NsPack"
                                  ": Unpacked and rebuilt executable\n");
      cli_multifree(dest, 0);
      cli_exe_info_destroy(peinfo);
      lseek(ndesc, 0, 0);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
      do {
      } while (0);
      if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) == CL_VIRUS) {
        close(ndesc);
        do {
        } while (0);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_VIRUS;
      }
      do {
      } while (0);
      close(ndesc);
      if (!ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
          free(tempfile);
          return CL_EUNLINK;
        }
      };
      free(tempfile);
      return CL_CLEAN;
      (void)0;
    default:
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_scanpe: NsPack"
                                ": Unpacking failed\n");
      close(ndesc);
      if (cli_unlink(tempfile)) {
        cli_exe_info_destroy(peinfo);
        free(tempfile);
        cli_multifree(dest, 0);
        return CL_EUNLINK;
      }
      cli_multifree(dest, 0);
      free(tempfile);
    };
    break;
  }

  ctx->corrupted_input = corrupted_cur;

  bc_ctx = cli_bytecode_context_alloc();
  if (!bc_ctx) {
    cli_errmsg("cli_scanpe: can't allocate memory for bc_ctx\n");
    return CL_EMEM;
  }

  cli_bytecode_context_setpe(bc_ctx, &pedata, peinfo->sections);
  cli_bytecode_context_setctx(bc_ctx, ctx);

  ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, BC_PE_UNPACKER, map);
  switch (ret) {
  case CL_VIRUS:
    cli_exe_info_destroy(peinfo);
    cli_bytecode_context_destroy(bc_ctx);

    return CL_VIRUS;
  case CL_SUCCESS:
    ndesc = cli_bytecode_context_getresult_file(bc_ctx, &tempfile);
    cli_bytecode_context_destroy(bc_ctx);
    if (ndesc != -1 && tempfile) {
      switch (1) {
      case 1:
        if (ctx->engine->keeptmp)
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal(
                    "cli_scanpe: bytecode PE hook"
                    ": Unpacked and rebuilt executable saved in %s\n",
                    tempfile);
        else
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("cli_scanpe: bytecode PE hook"
                                    ": Unpacked and rebuilt executable\n");
        cli_multifree(0);
        cli_exe_info_destroy(peinfo);
        lseek(ndesc, 0, 0);
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("***** Scanning rebuilt PE file *****\n");
        do {
        } while (0);
        if (cli_magic_scan_desc(ndesc, tempfile, ctx, ((void *)0)) ==
            CL_VIRUS) {
          close(ndesc);
          do {
          } while (0);
          if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile)) {
              free(tempfile);
              return CL_EUNLINK;
            }
          };
          free(tempfile);
          return CL_VIRUS;
        }
        do {
        } while (0);
        close(ndesc);
        if (!ctx->engine->keeptmp) {
          if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
          }
        };
        free(tempfile);
        return CL_CLEAN;
        (void)0;
      default:
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_scanpe: bytecode PE hook"
                                  ": Unpacking failed\n");
        close(ndesc);
        if (cli_unlink(tempfile)) {
          cli_exe_info_destroy(peinfo);
          free(tempfile);
          cli_multifree(0);
          return CL_EUNLINK;
        }
        cli_multifree(0);
        free(tempfile);
      };
    }

    break;
  default:
    cli_bytecode_context_destroy(bc_ctx);
  }

  cli_exe_info_destroy(peinfo);

  if ((ctx->options->general & 0x1) && viruses_found)
    return CL_VIRUS;

  return CL_CLEAN;
}

int cli_pe_targetinfo(fmap_t *map, struct cli_exe_info *peinfo) {
  return cli_peheader(map, peinfo, 0x4, ((void *)0));
}
int cli_peheader(fmap_t *map, struct cli_exe_info *peinfo, uint32_t opts,
                 cli_ctx *ctx) {
  uint16_t e_magic;
  const char *archtype = ((void *)0), *subsystem = ((void *)0);
  time_t timestamp;
  char timestr[32];
  uint32_t data_dirs_size;
  uint16_t opt_hdr_size;
  uint32_t stored_opt_hdr_size;
  struct pe_image_file_hdr *file_hdr;
  struct pe_image_optional_hdr32 *opt32;
  struct pe_image_optional_hdr64 *opt64;
  struct pe_image_section_hdr *section_hdrs = ((void *)0);
  unsigned int i, j, section_pe_idx;
  unsigned int err;
  uint32_t salign, falign;
  size_t fsize;
  ssize_t at;
  uint32_t is_dll = 0;
  uint32_t is_exe = 0;
  int native = 0;
  size_t read;

  int ret = -1;

  fsize = map->len - peinfo->offset;
  if (fmap_readn(map, &e_magic, peinfo->offset, sizeof(e_magic)) !=
      sizeof(e_magic)) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: Can't read DOS signature\n");
    goto done;
  }

  // P: dosHdr <- HEADER[0, sizeof DosHeader] as DosHeader
  // V1: OR (EQ dosHdr.e_magic 0x5a4d EQ dosHdr.e_magic 0x4d5a) term
  if (((uint16_t)(((const union unaligned_16 *)(&(e_magic)))->una_s16)) !=
          0x5a4d &&
      ((uint16_t)(((const union unaligned_16 *)(&(e_magic)))->una_s16)) !=
          0x4d5a) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: Invalid DOS signature\n");
    goto done;
  }

  // V2: UGE (INT FILESIZE 4) 0x40 term
  if (fmap_readn(map, &(peinfo->e_lfanew),
                 peinfo->offset + 58 + sizeof(e_magic),
                 sizeof(peinfo->e_lfanew)) != sizeof(peinfo->e_lfanew)) {

    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_peheader: Unable to read e_lfanew - truncated header?\n");
    ret = -2;
    goto done;
  }

  peinfo->e_lfanew = ((uint32_t)(
      ((const union unaligned_32 *)(&(peinfo->e_lfanew)))->una_s32));
  if (opts & 0x2) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("e_lfanew == %d\n", peinfo->e_lfanew);
  }

  // V3: NEQ dosHdr.e_lfanew 0 term
  if (!peinfo->e_lfanew) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: Not a PE file - e_lfanew == 0\n");
    goto done;
  }

  // V4: ULT (ADD dosHdr.e_lfanew sizeof pe_image_file_hdr) FILESIZE term
  if (fmap_readn(map, &(peinfo->file_hdr), peinfo->offset + peinfo->e_lfanew,
                 sizeof(struct pe_image_file_hdr)) !=
      sizeof(struct pe_image_file_hdr)) {

    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: Can't read file header\n");
    goto done;
  }

  // P: fileHdr <- HEADER[dosHdr.e_lfanew, pe_image_file_hdr] as pe_image_file_hdr
  file_hdr = &(peinfo->file_hdr);

  // V5: EQ fileHdr.Magic 0x4550
  if (((uint32_t)(
          ((const union unaligned_32 *)(&(file_hdr->Magic)))->una_s32)) !=
      0x00004550) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_peheader: Invalid PE signature (probably NE file)\n");
    goto done;
  }

  if (((uint16_t)(((const union unaligned_16 *)(&(file_hdr->Characteristics)))
                      ->una_s16)) &
      0x2000) {

    if (opts & 0x2) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("File type: DLL\n");
    }

    is_dll = 1;
  } else if (((uint16_t)(
                 ((const union unaligned_16 *)(&(file_hdr->Characteristics)))
                     ->una_s16)) &
             0x0002) {

    if (opts & 0x2) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("File type: Executable\n");
    }

    is_exe = 1;
  }

  // V6: OR (NEQ (BITAND fileHdr.Characteristics 2) 0) (NEQ (BITAND fileHdr.Characteristics 0x2000) 0) term
  if (!is_dll && !is_exe) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_peheader: Assumption Violated: PE is not a DLL or EXE\n");
  }

  peinfo->is_dll = is_dll;

  if (opts & 0x2 || opts & 0x1) {
    switch (((uint16_t)(
        ((const union unaligned_16 *)(&(file_hdr->Machine)))->una_s16))) {
    case 0x0:
      archtype = "Unknown";
      break;
    case 0x1:

      archtype = "Target Host";
      break;
    case 0x14c:
      archtype = "80386";
      break;
    case 0x14d:
      archtype = "80486";
      break;
    case 0x14e:
      archtype = "80586";
      break;
    case 0x160:
      archtype = "R3000 MIPS BE";
      break;
    case 0x162:
      archtype = "R3000 MIPS LE";
      break;
    case 0x166:
      archtype = "R4000 MIPS LE";
      break;
    case 0x168:
      archtype = "R10000 MIPS LE";
      break;
    case 0x169:
      archtype = "WCE MIPS LE";
      break;
    case 0x184:
      archtype = "DEC Alpha AXP";
      break;
    case 0x1a2:
      archtype = "Hitachi SH3 LE";
      break;
    case 0x1a3:
      archtype = "Hitachi SH3-DSP";
      break;
    case 0x1a4:
      archtype = "Hitachi SH3-E LE";
      break;
    case 0x1a6:
      archtype = "Hitachi SH4 LE";
      break;
    case 0x1a8:
      archtype = "Hitachi SH5";
      break;
    case 0x1c0:
      archtype = "ARM LE";
      break;
    case 0x1c2:
      archtype = "ARM Thumb/Thumb-2 LE";
      break;
    case 0x1c4:
      archtype = "ARM Thumb-2 LE";
      break;
    case 0x1d3:
      archtype = "AM33";
      break;
    case 0x1f0:
      archtype = "PowerPC LE";
      break;
    case 0x1f1:
      archtype = "PowerPC FP";
      break;
    case 0x200:
      archtype = "IA64";
      break;
    case 0x266:
      archtype = "MIPS16";
      break;
    case 0x268:
      archtype = "M68k";
      break;
    case 0x284:
      archtype = "DEC Alpha AXP 64bit";
      break;
    case 0x366:
      archtype = "MIPS+FPU";
      break;
    case 0x466:
      archtype = "MIPS16+FPU";
      break;
    case 0x520:
      archtype = "Infineon TriCore";
      break;
    case 0xcef:
      archtype = "CEF";
      break;
    case 0xebc:
      archtype = "EFI Byte Code";
      break;
    case 0x8664:
      archtype = "AMD64";
      break;
    case 0x9041:
      archtype = "M32R";
      break;
    case 0xaa64:
      archtype = "ARM64 LE";
      break;
    case 0xc0ee:
      archtype = "CEE";
      break;
    default:
      archtype = "Unknown";
    }

    if (opts & 0x2)
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("Machine type: %s\n", archtype);
  }

  // P: nSect <- fileHdr.NumberOfSections
  peinfo->nsections = ((uint16_t)(
      ((const union unaligned_16 *)(&(file_hdr->NumberOfSections)))->una_s16));
  // V7: AND (NEq nSect 0) (ULE nSect 96) term
  if (peinfo->nsections == 0 || peinfo->nsections > 96) {
    if (opts & 0x2 && !ctx->corrupted_input) {
      if (peinfo->nsections == 0) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_peheader: Invalid NumberOfSections (0)\n");
      } else {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_peheader: Invalid NumberOfSections (>%d)\n", 96);
      }
    }
    ret = -2;
    goto done;
  }

  timestamp = (time_t)((uint32_t)(
      ((const union unaligned_32 *)(&(file_hdr->TimeDateStamp)))->una_s32));
  // P: optSize <- fileHdr.SizeOfOptionalHeader
  opt_hdr_size = ((uint16_t)(
      ((const union unaligned_16 *)(&(file_hdr->SizeOfOptionalHeader)))
          ->una_s16));

  if (opts & 0x2) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("NumberOfSections: %d\n", peinfo->nsections);
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("TimeDateStamp: %s",
                              cli_ctime(&timestamp, timestr, sizeof(timestr)));
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("SizeOfOptionalHeader: 0x%x\n", opt_hdr_size);
  }
  // V8: UGE fileHdr.SizeOfOptionalHeader sizeof pe_image_optional_hdr32 term
  if (opt_hdr_size < sizeof(struct pe_image_optional_hdr32)) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: SizeOfOptionalHeader too small\n");

    ret = -2;
    goto done;
  }

  at = peinfo->offset + peinfo->e_lfanew + sizeof(struct pe_image_file_hdr);
  // P: optOffset <- ADD dosHdr.e_lfanew sizeof pe_image_file_hdr
  // V9: ULE (ADD optOffset sizeof pe_image_optional_hdr32) FILESIZE term
  if (fmap_readn(map, &(peinfo->pe_opt.opt32), at,
                 sizeof(struct pe_image_optional_hdr32)) !=
      sizeof(struct pe_image_optional_hdr32)) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_peheader: Can't read optional file header\n");
    ret = -2;
    goto done;
  }
  stored_opt_hdr_size = sizeof(struct pe_image_optional_hdr32);
  at += stored_opt_hdr_size;

  // P: optHdr <- HEADER[optOffset, sizeof pe_image_optional_hdr32] as pe_image_optional_hdr32
  opt32 = &(peinfo->pe_opt.opt32);

  // V10: EQ optHdr.Magic 0x20b
  if (((uint16_t)(((const union unaligned_16 *)(&(opt32->Magic)))->una_s16)) ==
      0x020b) {

    // V11(V9): UGE optSize sizeof pe_image_optional_hdr64 term
    if (opt_hdr_size < sizeof(struct pe_image_optional_hdr64)) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_peheader: Incorrect SizeOfOptionalHeader for PE32+\n");

      ret = -2;
      goto done;
    }

    // ### read remaining bytes of the OPT64 hdr
    // V12(V9): ULE (ADD optOffset sizeof pe_image_optional_hdr32) FILESIZE term
    if (fmap_readn(map,
                   (void *)(((size_t) & (peinfo->pe_opt.opt64)) +
                            sizeof(struct pe_image_optional_hdr32)),
                   at,
                   (sizeof(struct pe_image_optional_hdr64) -
                    sizeof(struct pe_image_optional_hdr32))) !=
        (sizeof(struct pe_image_optional_hdr64) -
         sizeof(struct pe_image_optional_hdr32))) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_peheader: Can't read additional optional "
                                "file header bytes\n");
      ret = -2;
      goto done;
    }

    stored_opt_hdr_size += (sizeof(struct pe_image_optional_hdr64) -
                            sizeof(struct pe_image_optional_hdr32));
    at += (sizeof(struct pe_image_optional_hdr64) -
           sizeof(struct pe_image_optional_hdr32));
    peinfo->is_pe32plus = 1;

    // P(V10): optHdr64 <- HEADER[optOffset, sizeof pe_image_optional_hdr64] as pe_image_optional_hdr32
    opt64 = &(peinfo->pe_opt.opt64);

    // P(V10): vep <- optHdr64.AddressOfEntryPoint
    peinfo->vep = ((uint32_t)(
        ((const union unaligned_32 *)(&(opt64->AddressOfEntryPoint)))
            ->una_s32));
    // P(V10): hdrSize <- optHdr64.SizeOfHeaders
    peinfo->hdr_size = ((uint32_t)(
        ((const union unaligned_32 *)(&(opt64->SizeOfHeaders)))->una_s32));
    // P(V10): nDirs <- optHdr64.NumberOfRvaAndSizes
    peinfo->ndatadirs = ((uint32_t)(
        ((const union unaligned_32 *)(&(opt64->NumberOfRvaAndSizes)))
            ->una_s32));

    if (opts & 0x2) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("File format: PE32+\n");
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MajorLinkerVersion: %d\n",
                                opt64->MajorLinkerVersion);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MinorLinkerVersion: %d\n",
                                opt64->MinorLinkerVersion);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "SizeOfCode: 0x%x\n",
                ((uint32_t)(((const union unaligned_32 *)(&(opt64->SizeOfCode)))
                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("SizeOfInitializedData: 0x%x\n",
                                ((uint32_t)(((const union unaligned_32 *)(&(
                                                 opt64->SizeOfInitializedData)))
                                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "SizeOfUninitializedData: 0x%x\n",
                ((uint32_t)(((const union unaligned_32 *)(&(
                                 opt64->SizeOfUninitializedData)))
                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("AddressOfEntryPoint: 0x%x\n", peinfo->vep);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "BaseOfCode: 0x%x\n",
                ((uint32_t)(((const union unaligned_32 *)(&(opt64->BaseOfCode)))
                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("SectionAlignment: 0x%x\n",
                                ((uint32_t)(((const union unaligned_32 *)(&(
                                                 opt64->SectionAlignment)))
                                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("FileAlignment: 0x%x\n",
                                ((uint32_t)(((const union unaligned_32 *)(&(
                                                 opt64->FileAlignment)))
                                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MajorSubsystemVersion: %d\n",
                                ((uint16_t)(((const union unaligned_16 *)(&(
                                                 opt64->MajorSubsystemVersion)))
                                                ->una_s16)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MinorSubsystemVersion: %d\n",
                                ((uint16_t)(((const union unaligned_16 *)(&(
                                                 opt64->MinorSubsystemVersion)))
                                                ->una_s16)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("SizeOfImage: 0x%x\n",
                                ((uint32_t)(((const union unaligned_32 *)(&(
                                                 opt64->SizeOfImage)))
                                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("SizeOfHeaders: 0x%x\n", peinfo->hdr_size);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("NumberOfRvaAndSizes: %u\n", peinfo->ndatadirs);
    }
  } else {
    peinfo->is_pe32plus = 0;
    // P(!V10): vep <- optHdr.AddressOfEntryPoint
    peinfo->vep = ((uint32_t)(
        ((const union unaligned_32 *)(&(opt32->AddressOfEntryPoint)))
            ->una_s32));
    // P(!V10): hdrSize <- optHdr.SizeOfHeaders
    peinfo->hdr_size = ((uint32_t)(
        ((const union unaligned_32 *)(&(opt32->SizeOfHeaders)))->una_s32));
    // P(!V10): nDirs <- optHdr.NumberOfRvaAndSizes
    peinfo->ndatadirs = ((uint32_t)(
        ((const union unaligned_32 *)(&(opt32->NumberOfRvaAndSizes)))
            ->una_s32));

    if (opts & 0x2) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("File format: PE\n");
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MajorLinkerVersion: %d\n",
                                opt32->MajorLinkerVersion);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MinorLinkerVersion: %d\n",
                                opt32->MinorLinkerVersion);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "SizeOfCode: 0x%x\n",
                ((uint32_t)(((const union unaligned_32 *)(&(opt32->SizeOfCode)))
                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("SizeOfInitializedData: 0x%x\n",
                                ((uint32_t)(((const union unaligned_32 *)(&(
                                                 opt32->SizeOfInitializedData)))
                                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "SizeOfUninitializedData: 0x%x\n",
                ((uint32_t)(((const union unaligned_32 *)(&(
                                 opt32->SizeOfUninitializedData)))
                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("AddressOfEntryPoint: 0x%x\n", peinfo->vep);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "BaseOfCode: 0x%x\n",
                ((uint32_t)(((const union unaligned_32 *)(&(opt32->BaseOfCode)))
                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("SectionAlignment: 0x%x\n",
                                ((uint32_t)(((const union unaligned_32 *)(&(
                                                 opt32->SectionAlignment)))
                                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("FileAlignment: 0x%x\n",
                                ((uint32_t)(((const union unaligned_32 *)(&(
                                                 opt32->FileAlignment)))
                                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MajorSubsystemVersion: %d\n",
                                ((uint16_t)(((const union unaligned_16 *)(&(
                                                 opt32->MajorSubsystemVersion)))
                                                ->una_s16)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("MinorSubsystemVersion: %d\n",
                                ((uint16_t)(((const union unaligned_16 *)(&(
                                                 opt32->MinorSubsystemVersion)))
                                                ->una_s16)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("SizeOfImage: 0x%x\n",
                                ((uint32_t)(((const union unaligned_32 *)(&(
                                                 opt32->SizeOfImage)))
                                                ->una_s32)));
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("SizeOfHeaders: 0x%x\n", peinfo->hdr_size);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("NumberOfRvaAndSizes: %u\n", peinfo->ndatadirs);
    }
  }

  // P: salign <- optHdr.SectionAlignment
  // P(V10): salign <-optHdr64.SectionAlignment
  salign = (peinfo->is_pe32plus)
               ? ((uint32_t)(
                     ((const union unaligned_32 *)(&(opt64->SectionAlignment)))
                         ->una_s32))
               : ((uint32_t)(
                     ((const union unaligned_32 *)(&(opt32->SectionAlignment)))
                         ->una_s32));
  // P: falign <- optHdr.FileAlignment
  // P(V10): falign <-optHdr64.FileAlignment  
  falign =
      (peinfo->is_pe32plus)
          ? ((uint32_t)(((const union unaligned_32 *)(&(opt64->FileAlignment)))
                            ->una_s32))
          : ((uint32_t)(((const union unaligned_32 *)(&(opt32->FileAlignment)))
                            ->una_s32));

  // P: subsystem <- optHdr.Subsystem
  // P(V10): <- subsystem <-optHdr64.Subsustem
  switch (
      peinfo->is_pe32plus
          ? ((uint16_t)(
                ((const union unaligned_16 *)(&(opt64->Subsystem)))->una_s16))
          : ((uint16_t)(((const union unaligned_16 *)(&(opt32->Subsystem)))
                            ->una_s16))) {
  case 0:
    subsystem = "Unknown";
    break;
  case 1:
    subsystem = "Native (svc)";
    native = 1;
    break;
  case 2:
    subsystem = "Win32 GUI";
    break;
  case 3:
    subsystem = "Win32 console";
    break;
  case 5:
    subsystem = "OS/2 console";
    break;
  case 7:
    subsystem = "POSIX console";
    break;
  case 8:
    subsystem = "Native Win9x driver";
    break;
  case 9:
    subsystem = "WinCE GUI";
    break;
  case 10:
    subsystem = "EFI application";
    break;
  case 11:
    subsystem = "EFI driver";
    break;
  case 12:
    subsystem = "EFI runtime driver";
    break;
  case 13:
    subsystem = "EFI ROM image";
    break;
  case 14:
    subsystem = "Xbox";
    break;
  case 16:
    subsystem = "Boot application";
    break;
  default:
    subsystem = "Unknown";
  }

  if (opts & 0x2) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("Subsystem: %s\n", subsystem);
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("------------------------------------\n");
  }

  // V13: OR (EQ subsystem 1) (OR (NEQ salign 0) (ISALIGNED salign 0x1000)) term
  if (!native && (!salign || (salign % 0x1000))) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: Bad section alignment\n");
    if (opts & 0x8) {
      ret = -2;
      goto done;
    }
  }

  // V14: OR (EQ subsystem 1) (OR (NEQ falign 0) (ISALIGNED falign 0x200)) term
  if (!native && (!falign || (falign % 0x200))) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: Bad file alignment\n");
    if (opts & 0x8) {
      ret = -2;
      goto done;
    }
  }
  if (peinfo->ndatadirs > 0x10) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: Encountered NumberOfRvaAndSizes > "
                              "16 (suspicious)\n");
  }

  if (peinfo->ndatadirs < sizeof(peinfo->dirs) / sizeof(peinfo->dirs[0])) {
    memset(&(peinfo->dirs), '\0', sizeof(peinfo->dirs));
  }

  // ### consider only the first 16 directories, even if nDirs is greater than the number 16 (common directory number)
  // V15: UGT nDirs 16
  // P(V15): nDirs <- INT 16 4
  peinfo->ndatadirs =
      ((peinfo->ndatadirs) < (sizeof(peinfo->dirs) / sizeof(peinfo->dirs[0]))
           ? (peinfo->ndatadirs)
           : (sizeof(peinfo->dirs) / sizeof(peinfo->dirs[0])));

  // P: dirSize <- MUL nDirs sizeof pe_image_data_dir
  data_dirs_size = sizeof(struct pe_image_data_dir) * peinfo->ndatadirs;

  // V16(V10): UGE optSize (ADD dirSize sizeof pe_image_optional_hdr64) term
  // V17(!V10): UGE optSize (ADD dirSize sizeof pe_image_optional_hdr32) term
  if (opt_hdr_size < (stored_opt_hdr_size + data_dirs_size)) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: SizeOfOptionalHeader too small "
                              "(doesn't include data dir size)\n");
    ret = -2;
    goto done;
  }

  // P(V10): dirsOffset <- ADD optOffset sizeof pe_image_optional_hdr64
  // P(!V10): dirsOffset <- ADD optOffset sizeof pe_image_optional_hdr32
  // V18: ULT ADD dirsOffset dirSize FILESIZE term
  read = fmap_readn(map, peinfo->dirs, at, data_dirs_size);
  if ((read == (size_t)-1) || (read != data_dirs_size)) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_peheader: Can't read optional file header data dirs\n");
    goto done;
  }
  at += data_dirs_size;

  // P: sectTableOff <- ADD dirsOffset dirSize
  // V19(V10): UGT filHdr.SizeOfOptionalHeader (ADD dirSize sizeof pe_image_optional_hdr64)
  // P(V19): sectTableOff <- ADD optOffset filHdr.SizeOfOptionalHeader
  // V20(!V10): UGT filHdr.SizeOfOptionalHeader (ADD dirSize sizeof pe_image_optional_hdr32)
  // P(V20): sectTableOff <- ADD optOffset filHdr.SizeOfOptionalHeader
  if (opt_hdr_size != (stored_opt_hdr_size + data_dirs_size)) {

    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_peheader: Encountered case where SizeOfOptionalHeader "
              "appears bigger than required\n");
    at += opt_hdr_size - (stored_opt_hdr_size + data_dirs_size);
  }

  if (peinfo->hdr_size != (((salign))
                               ? (((peinfo->hdr_size) / (salign) +
                                   ((peinfo->hdr_size) % (salign) != 0)) *
                                  (salign))
                               : (peinfo->hdr_size))) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: SizeOfHeader is not aligned to "
                              "the SectionAlignment\n");
  }
  if (peinfo->hdr_size != (((falign))
                               ? (((peinfo->hdr_size) / (falign) +
                                   ((peinfo->hdr_size) % (falign) != 0)) *
                                  (falign))
                               : (peinfo->hdr_size))) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: SizeOfHeader is not aligned to "
                              "the FileAlignment\n");
  }

  // P: hdrSize <- ALIGNUP hdrSize salign
  peinfo->hdr_size = (((salign)) ? (((peinfo->hdr_size) / (salign) +
                                     ((peinfo->hdr_size) % (salign) != 0)) *
                                    (salign))
                                 : (peinfo->hdr_size));

  peinfo->sections = (struct cli_exe_section *)cli_calloc(
      peinfo->nsections, sizeof(struct cli_exe_section));

  if (!peinfo->sections) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_peheader: Can't allocate memory for section headers\n");
    goto done;
  }

  section_hdrs = (struct pe_image_section_hdr *)cli_calloc(
      peinfo->nsections, sizeof(struct pe_image_section_hdr));

  if (!section_hdrs) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_peheader: Can't allocate memory for section headers\n");
    goto done;
  }

  // V21: ULE (ADD (MUL nSect sizeof pe_image_section_hdr) sectTableOff) FILESIZE term
  read = fmap_readn(map, section_hdrs, at,
                    peinfo->nsections * sizeof(struct pe_image_section_hdr));
  if ((read == (size_t)-1) ||
      (read != peinfo->nsections * sizeof(struct pe_image_section_hdr))) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: Can't read section header - "
                              "possibly broken PE file\n");
    ret = -2;
    goto done;
  }
  at += sizeof(struct pe_image_section_hdr) * peinfo->nsections;

  // V22: NEq falign 0x200
  // L1(V22): section <- LOOP(HEADER, sectTableOFF, sizeof pe_image_section_hdr, nSect, 5) as pe_image_section_hdr
  for (i = 0; falign != 0x200 && i < peinfo->nsections; i++) {

    // V23: AND (AND (NEq falign 0) (NEq section.SizeOfRawData 0)) (AND (ISALIGNED section.PointerToRawData falign) (NOT ISALIGNED 0x200))
    if (falign && section_hdrs[i].SizeOfRawData &&
        ((uint32_t)(
            ((const union unaligned_32 *)(&(section_hdrs[i].PointerToRawData)))
                ->una_s32)) %
            falign &&
        !(((uint32_t)(((const union unaligned_32 *)(&(
                           section_hdrs[i].PointerToRawData)))
                          ->una_s32)) %
          0x200)) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_peheader: Encountered section with unexpected alignment - "
                "triggering fallback mode\n");
      // P(V23): falign <- 0x200
      falign = 0x200;
    }
  }
  // END L1
  fsize = (map->len - peinfo->offset);

  // V24: NEQ salign 0 term
  // V25: NEQ falign 0
  // P: expected_rva <- hdrSize
  // P: ep_found <- INT 0 1
  // L2: section2 <- LOOP(HEADER, sectTableOFF, sizeof pe_image_section_hdr, nSect, 5) as pe_image_section_hdr
  for (i = 0, section_pe_idx = 0; i < peinfo->nsections;
       i++, section_pe_idx++) {

    struct cli_exe_section *section = &(peinfo->sections[i]);
    struct pe_image_section_hdr *section_hdr = &(section_hdrs[i]);
    char sname[9];

    // P: rva <- ALIGNDOWN section.VirtualAddress salign
    section->rva =
        (((salign)) ? (((((uint32_t)(((const union unaligned_32 *)(&(
                                          section_hdr->VirtualAddress)))
                                         ->una_s32))) /
                        (salign)) *
                       (salign))
                    : (((uint32_t)(((const union unaligned_32 *)(&(
                                        section_hdr->VirtualAddress)))
                                       ->una_s32))));
    // P: vsz <- ALIGNUP section.VirtualSize salign
    section->vsz =
        (((salign))
             ? (((((uint32_t)(
                     ((const union unaligned_32 *)(&(section_hdr->VirtualSize)))
                         ->una_s32))) /
                     (salign) +
                 ((((uint32_t)(((const union unaligned_32 *)(&(
                                    section_hdr->VirtualSize)))
                                   ->una_s32))) %
                      (salign) !=
                  0)) *
                (salign))
             : (((uint32_t)(
                   ((const union unaligned_32 *)(&(section_hdr->VirtualSize)))
                       ->una_s32))));

    // P: raw <- section.PointerToRawData
    // P(V25): raw <- ALIGNDOWN section.PointerToRawData falign
    section->raw =
        (((falign)) ? (((((uint32_t)(((const union unaligned_32 *)(&(
                                          section_hdr->PointerToRawData)))
                                         ->una_s32))) /
                        (falign)) *
                       (falign))
                    : (((uint32_t)(((const union unaligned_32 *)(&(
                                        section_hdr->PointerToRawData)))
                                       ->una_s32))));
    // P: rsz <- section.SizOfRawData
    // P(V25): rsz <- ALIGNUP section.SizOfRawData falign
    section->rsz =
        (((falign))
             ? (((((uint32_t)(((const union unaligned_32 *)(&(
                                   section_hdr->SizeOfRawData)))
                                  ->una_s32))) /
                     (falign) +
                 ((((uint32_t)(((const union unaligned_32 *)(&(
                                    section_hdr->SizeOfRawData)))
                                   ->una_s32))) %
                      (falign) !=
                  0)) *
                (falign))
             : (((uint32_t)(
                   ((const union unaligned_32 *)(&(section_hdr->SizeOfRawData)))
                       ->una_s32))));
    section->chr = ((uint32_t)(
        ((const union unaligned_32 *)(&(section_hdr->Characteristics)))
            ->una_s32));
    // P: urva <- section.VirtualAddress
    section->urva = ((uint32_t)(
        ((const union unaligned_32 *)(&(section_hdr->VirtualAddress)))
            ->una_s32));
    // P: uvsz <- section.VirtualSize
    section->uvsz = ((uint32_t)(
        ((const union unaligned_32 *)(&(section_hdr->VirtualSize)))->una_s32));
    // P: uraw <- section.PointerToRawData
    section->uraw = ((uint32_t)(
        ((const union unaligned_32 *)(&(section_hdr->PointerToRawData)))
            ->una_s32));
    // P: uraw <- section.SizeOfRawData
    section->ursz = ((uint32_t)(
        ((const union unaligned_32 *)(&(section_hdr->SizeOfRawData)))
            ->una_s32));

    // V26: NEQ rsz 0
    if (section->rsz) {
      // V27(V26): OR (UGE raw FILESIZE) (UGE uraw FILESIZE)
      if (section->raw >= fsize || section->uraw >= fsize) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_peheader: Broken PE file - Section %d starts or exists "
                  "beyond the end of file (Offset@ %lu, Total filesize %lu)\n",
                  section_pe_idx, (unsigned long)section->raw,
                  (unsigned long)fsize);

        // # assuming this is FALSE
        if (opts & 0x10) {
          if (peinfo->nsections == 1) {
            ret = -2;
            goto done;
          }

          for (j = i; j < peinfo->nsections - 1; j++)
            memcpy(&(peinfo->sections[j]), &(peinfo->sections[j + 1]),
                   sizeof(struct cli_exe_section));

          for (j = i; j < peinfo->nsections - 1; j++)
            memcpy(&section_hdrs[j], &section_hdrs[j + 1],
                   sizeof(struct pe_image_section_hdr));

          peinfo->nsections--;

          i--;
          continue;

        } else {
          section->rsz = 0;
          section->ursz = 0;
        }
      // P(V27): rsz <- INT 0 4
      // P(V27): ursz <- INT 0 4
      } else {
        // V28(V26, !V27): ULE (ADD rsz raw) FILESIZE
        if (!((size_t)(fsize) > 0 && (size_t)(section->rsz) > 0 &&
              (size_t)(section->rsz) <= (size_t)(fsize) &&
              (ptrdiff_t)(section->raw) >= (ptrdiff_t)(0) &&
              (ptrdiff_t)(section->raw) + (ptrdiff_t)(section->rsz) <=
                  (ptrdiff_t)(0) + (ptrdiff_t)(fsize) &&
              (ptrdiff_t)(section->raw) + (ptrdiff_t)(section->rsz) >
                  (ptrdiff_t)(0) &&
              (ptrdiff_t)(section->raw) <
                  (ptrdiff_t)(0) + (ptrdiff_t)(fsize))) {
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal(
                    "cli_peheader: PE Section %d raw+rsz extends past the end "
                    "of the file by %lu bytes\n",
                    section_pe_idx, (section->raw + section->rsz) - fsize);
          // P(V28): rsz <- SUB (INT FILESIZE 4) raw
          section->rsz = fsize - section->raw;
        }

        // V29(V26, !V27): ULE (ADD ursz uraw) FILESIZE
        if (!((size_t)(fsize) > 0 && (size_t)(section->ursz) > 0 &&
              (size_t)(section->ursz) <= (size_t)(fsize) &&
              (ptrdiff_t)(section->uraw) >= (ptrdiff_t)(0) &&
              (ptrdiff_t)(section->uraw) + (ptrdiff_t)(section->ursz) <=
                  (ptrdiff_t)(0) + (ptrdiff_t)(fsize) &&
              (ptrdiff_t)(section->uraw) + (ptrdiff_t)(section->ursz) >
                  (ptrdiff_t)(0) &&
              (ptrdiff_t)(section->uraw) <
                  (ptrdiff_t)(0) + (ptrdiff_t)(fsize))) {
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal(
                    "cli_peheader: PE Section %d uraw+ursz extends past the "
                    "end of the file by %lu bytes\n",
                    section_pe_idx, (section->uraw + section->ursz) - fsize);
          // P(V29): ursz <- SUB (INT FILESIZE 4) uraw
          section->ursz = fsize - section->uraw;
        }
      }
    }

    strncpy(sname, (char *)section_hdr->Name, 8);
    sname[8] = '\0';
    // # these are redundant
    // # V30: AND (EQ vsz 0) (NEQ rsz 0)
    if (!section->vsz && section->rsz)
      // # P(V30) vsz <- ALIGNUP ursz salign
      section->vsz = (((salign)) ? (((section->ursz) / (salign) +
                                     ((section->ursz) % (salign) != 0)) *
                                    (salign))
                                 : (section->ursz));

    if (opts & 0x2) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("Section %d\n", section_pe_idx);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("Section name: %s\n", sname);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("Section data (from headers - in memory)\n");
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("VirtualSize: 0x%x 0x%x\n", section->uvsz,
                                section->vsz);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("VirtualAddress: 0x%x 0x%x\n", section->urva,
                                section->rva);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("SizeOfRawData: 0x%x 0x%x\n", section->ursz,
                                section->rsz);
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("PointerToRawData: 0x%x 0x%x\n", section->uraw,
                                section->raw);

      if (section->chr & 0x20) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("Section contains executable code\n");
      }

      if (section->vsz < section->rsz) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("Section contains free space\n");
      }

      if (section->chr & 0x20000000)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("Section's memory is executable\n");

      if (section->chr & 0x80000000)
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("Section's memory is writeable\n");

      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("------------------------------------\n");
    }

    // V31: ISALIGNED urva salign term
    if (!salign || (section->urva % salign)) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_peheader: Broken PE - section's "
                                "VirtualAddress is misaligned\n");
      if (opts & 0x8) {
        ret = -2;
        goto done;
      }
    }

    // V32: (NEQ BITAND urva[3] 0x80 0) term
    // V33: (NEQ BITAND uvsz[3] 0x80 0) term
    // V34: OR (EQ rsz 0) (NEQ BITAND uvsz[3] 0x80 0) term
    // V35: (NEQ BITAND ursz[3] 0x80 0) term
    if (section->urva >> 31 || section->uvsz >> 31 ||
        (section->rsz && section->uraw >> 31) ||
        peinfo->sections[i].ursz >> 31) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_peheader: Found PE values with sign bit set\n");
      ret = -2;
      goto done;
    }

    // ##### the following if-else can be modeled easily introducing the hidden variable expected_rva, which is set to hdrSize before the loop and updated to the end of the current section at the end of the iteration
    // V36: EQ urva expected_rva term
    // P: expected_rva <- ADD urva vsz
    if (!i) {
      if (section->urva != peinfo->hdr_size) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("cli_peheader: First section doesn't start "
                                  "immediately after the header\n");
        if (opts & 0x8) {
          ret = -2;
          goto done;
        }
      }

      peinfo->min = section->rva;
      peinfo->max = section->rva + section->rsz;
    } else {
      if (section->urva - peinfo->sections[i - 1].urva !=
          peinfo->sections[i - 1].vsz) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_peheader: Virtually misplaced section (wrong order, "
                  "overlapping, non contiguous)\n");
        if (opts & 0x8) {
          ret = -2;
          goto done;
        }
      }

      if (section->rva < peinfo->min)
        peinfo->min = section->rva;

      if (section->rva + section->rsz > peinfo->max) {
        peinfo->max = section->rva + section->rsz;
        peinfo->overlay_start = section->raw + section->rsz;
      }

      if (section->raw + section->rsz > peinfo->max) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "cli_peheader: Assumption Violated: Last section end RVA "
                  "isn't tied to the last section\n");
      }
    }
    // END L2
    // #### Check whether the current section contains the EntryPoint. This check is a few lines below
    // V37: AND (AND (UGE optHdr.AddressOfEntryPoint rva) (UGT rsz (SUB optHdr.AddressOfEntryPoint rva))) (NEQ rsz 0)
    // P(V37): ep_found <- INT 1 1
  }

  peinfo->overlay_size = fsize - peinfo->overlay_start;

  // V38: NEQ ep_found 0 term
  if (!(peinfo->ep =
            cli_rawaddr(peinfo->vep, peinfo->sections, peinfo->nsections, &err,
                        fsize, peinfo->hdr_size)) &&
      err) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_peheader: Broken PE file - Can't map "
                              "EntryPoint to a file offset\n");
    ret = -2;
    goto done;
  }
  if (opts & 0x2) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("EntryPoint offset: 0x%x (%d)\n", peinfo->ep,
                              peinfo->ep);
  }

  if (is_dll || peinfo->ndatadirs < 3 || !peinfo->dirs[2].Size)
    peinfo->res_addr = 0;
  else
    peinfo->res_addr = ((uint32_t)(
        ((const union unaligned_32 *)(&(peinfo->dirs[2].VirtualAddress)))
            ->una_s32));

  while (opts & 0x4 && peinfo->ndatadirs >= 3 && peinfo->dirs[2].Size) {
    struct vinfo_list vlist;
    const uint8_t *vptr, *baseptr;
    uint32_t rva, res_sz;

    if (0 != peinfo->offset) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_peheader: Assumption Violated: Looking "
                                "for version info when peinfo->offset != 0\n");
    }

    memset(&vlist, 0, sizeof(vlist));
    findres(0x10, 0xffffffff, map, peinfo, versioninfo_cb, &vlist);
    if (!vlist.count)
      break;

    if (cli_hashset_init(&peinfo->vinfo, 32, 80)) {
      cli_errmsg("cli_peheader: Unable to init vinfo hashset\n");
      goto done;
    }

    err = 0;
    for (i = 0; i < vlist.count; i++) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_peheader: parsing version info @ rva %x (%u/%u)\n",
                vlist.rvas[i], i + 1, vlist.count);
      rva = cli_rawaddr(vlist.rvas[i], peinfo->sections, peinfo->nsections,
                        &err, fsize, peinfo->hdr_size);
      if (err)
        continue;

      if (!(vptr = fmap_need_off_once(map, rva, 16)))
        continue;

      baseptr = vptr - rva;

      rva = (((const union unaligned_32 *)(vptr))->una_s32);
      res_sz = (((const union unaligned_32 *)(vptr + 4))->una_s32);
      rva = cli_rawaddr(rva, peinfo->sections, peinfo->nsections, &err, fsize,
                        peinfo->hdr_size);
      if (err)
        continue;
      if (!(vptr = fmap_need_off_once(map, rva, res_sz)))
        continue;

      while (res_sz > 4) {
        uint32_t vinfo_sz, vinfo_val_sz, got_varfileinfo = 0;

        vinfo_sz = vinfo_val_sz =
            (((const union unaligned_32 *)(vptr))->una_s32);
        vinfo_sz &= 0xffff;
        if (vinfo_sz > res_sz)
          break;

        vinfo_val_sz >>= 16;
        if (vinfo_sz <= 6 + 0x20 + 2 + 0x34 || vinfo_val_sz != 0x34 ||
            memcmp(vptr + 6,
                   "V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0\0", 0x20) ||
            (unsigned int)(((const union unaligned_32 *)(vptr + 0x28))
                               ->una_s32) != 0xfeef04bd) {

          break;
        }

        vptr += 6 + 0x20 + 2 + 0x34;
        vinfo_sz -= 6 + 0x20 + 2 + 0x34;

        while (vinfo_sz > 6) {
          uint32_t sfi_sz =
              (((const union unaligned_32 *)(vptr))->una_s32) & 0xffff;

          if (sfi_sz > vinfo_sz)
            break;

          if (!got_varfileinfo && sfi_sz > 6 + 0x18 &&
              !memcmp(vptr + 6, "V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0",
                      0x18)) {

            vptr += sfi_sz;
            vinfo_sz -= sfi_sz;
            got_varfileinfo = 1;
            continue;
          }

          if (sfi_sz <= 6 + 0x1e ||
              memcmp(vptr + 6, "S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0",
                     0x1e)) {

            break;
          }

          vptr += 6 + 0x1e;
          sfi_sz -= 6 + 0x1e;

          while (sfi_sz > 6) {
            uint32_t st_sz =
                (((const union unaligned_32 *)(vptr))->una_s32) & 0xffff;
            const uint8_t *next_vptr = vptr + st_sz;
            uint32_t next_sfi_sz = sfi_sz - st_sz;

            if (st_sz > sfi_sz || st_sz <= 24) {

              break;
            }

            vptr += 24;
            st_sz -= 24;

            while (st_sz > 6) {
              uint32_t s_sz, s_key_sz, s_val_sz;

              s_sz =
                  ((((const union unaligned_32 *)(vptr))->una_s32) & 0xffff) +
                  3;
              s_sz &= ~3;
              if (s_sz > st_sz || s_sz <= 6 + 2 + 8) {

                st_sz = 0;
                sfi_sz = 0;
                break;
              }

              for (s_key_sz = 6; s_key_sz + 1 < s_sz; s_key_sz += 2) {
                if (vptr[s_key_sz] || vptr[s_key_sz + 1])
                  continue;

                s_key_sz += 2;
                break;
              }

              s_key_sz += 3;
              s_key_sz &= ~3;

              if (s_key_sz >= s_sz) {

                vptr += s_sz;
                st_sz -= s_sz;
                continue;
              }

              s_val_sz = s_sz - s_key_sz;
              s_key_sz -= 6;

              if (s_val_sz <= 2) {

                vptr += s_sz;
                st_sz -= s_sz;
                continue;
              }

              if (cli_hashset_addkey(&peinfo->vinfo,
                                     (uint32_t)(vptr - baseptr + 6))) {
                cli_errmsg(
                    "cli_peheader: Unable to add rva to vinfo hashset\n");
                goto done;
              }

              if (cli_debug_flag) {
                char *k, *v, *s;

                k = cli_utf16toascii((const char *)vptr + 6, s_key_sz);
                if (k) {
                  v = cli_utf16toascii((const char *)vptr + s_key_sz + 6,
                                       s_val_sz);
                  if (v) {
                    s = cli_str2hex((const char *)vptr + 6,
                                    s_key_sz + s_val_sz);
                    if (s) {
                      (!__builtin_expect(!!(cli_debug_flag), 0))
                          ? (void)0
                          : cli_dbgmsg_internal(
                                "VersionInfo (%x): '%s'='%s' - VI:%s\n",
                                (uint32_t)(vptr - baseptr + 6), k, v, s);
                      free(s);
                    }
                    free(v);
                  }
                  free(k);
                }
              }
              vptr += s_sz;
              st_sz -= s_sz;
            }
            vptr = next_vptr;
            sfi_sz = next_sfi_sz * (sfi_sz != 0);
          }
          break;
        }
        break;
      }
    }
    break;
  }

  peinfo->is_dll = is_dll;

  ret = 0;

done:

  if (((void *)0) != section_hdrs) {
    free(section_hdrs);
  }

  return ret;
}

static int sort_sects(const void *first, const void *second) {
  const struct cli_exe_section *a = first, *b = second;
  return (a->raw - b->raw);
}
cl_error_t cli_check_auth_header(cli_ctx *ctx, struct cli_exe_info *peinfo) {
  size_t at;
  unsigned int i, hlen;
  size_t fsize;
  fmap_t *map = *ctx->fmap;
  void *hashctx = ((void *)0);
  struct pe_certificate_hdr cert_hdr;
  struct cli_mapped_region *regions = ((void *)0);
  unsigned int nregions;
  cl_error_t ret = CL_EVERIFY;
  uint8_t authsha1[20];
  uint32_t sec_dir_offset;
  uint32_t sec_dir_size;
  struct cli_exe_info _peinfo;

  if (!(ctx->dconf->pe & 0x20000))
    return CL_EVERIFY;

  if (ctx->engine->engine_options & 0x8)
    return CL_EVERIFY;

  if (((void *)0) == peinfo) {
    peinfo = &_peinfo;
    cli_exe_info_init(peinfo, 0);

    if (cli_peheader(*ctx->fmap, peinfo, 0x0, ((void *)0)) != 0) {
      cli_exe_info_destroy(peinfo);
      return CL_EFORMAT;
    }
  }

  sec_dir_offset = ((uint32_t)(
      ((const union unaligned_32 *)(&(peinfo->dirs[4].VirtualAddress)))
          ->una_s32));
  sec_dir_size = ((uint32_t)(
      ((const union unaligned_32 *)(&(peinfo->dirs[4].Size)))->una_s32));

  if (sec_dir_size < 8 &&
      !cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA1, 2)) {
    ret = CL_BREAK;
    goto finish;
  }
  fsize = map->len;

  regions = (struct cli_mapped_region *)cli_calloc(
      4, sizeof(struct cli_mapped_region));
  if (!regions) {
    ret = CL_EMEM;
    goto finish;
  }
  nregions = 0;
  ret = CL_EFORMAT;

  at = 0;
  hlen = peinfo->e_lfanew + sizeof(struct pe_image_file_hdr) +
         (peinfo->is_pe32plus
              ? __builtin_offsetof(struct pe_image_optional_hdr64, CheckSum)
              : __builtin_offsetof(struct pe_image_optional_hdr32, CheckSum));
  do {
    regions[nregions].offset = (0);
    regions[nregions].size = (hlen);
    nregions++;
  } while (0);
  at = hlen + 4;

  if (peinfo->is_pe32plus)
    hlen = sizeof(struct pe_image_optional_hdr64) -
           __builtin_offsetof(struct pe_image_optional_hdr64, CheckSum) - 4;
  else
    hlen = sizeof(struct pe_image_optional_hdr32) -
           __builtin_offsetof(struct pe_image_optional_hdr32, CheckSum) - 4;

  hlen += sizeof(struct pe_image_data_dir) * 4;
  do {
    regions[nregions].offset = (at);
    regions[nregions].size = (hlen);
    nregions++;
  } while (0);
  at += hlen + 8;

  if (at > peinfo->hdr_size) {
    goto finish;
  }

  if (sec_dir_offset) {

    if (fsize != sec_dir_size + sec_dir_offset) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_check_auth_header: expected authenticode "
                                "data at the end of the file\n");
      goto finish;
    }

    if (at < sec_dir_offset) {
      hlen = sec_dir_offset - at;
      do {
        regions[nregions].offset = (at);
        regions[nregions].size = (hlen);
        nregions++;
      } while (0);
    } else if (at > sec_dir_offset) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_check_auth_header: security directory offset appears to "
                "overlap with the PE header\n");
      goto finish;
    }

    if (fmap_readn(map, &cert_hdr, sec_dir_offset, sizeof(cert_hdr)) !=
        sizeof(cert_hdr)) {
      goto finish;
    }

    if (((uint16_t)(
            ((const union unaligned_16 *)(&(cert_hdr.revision)))->una_s16)) !=
        0x0200) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal("cli_check_auth_header: unsupported "
                                "authenticode data revision\n");
      goto finish;
    }

    if (((uint16_t)(
            ((const union unaligned_16 *)(&(cert_hdr.type)))->una_s16)) !=
        0x0002) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_check_auth_header: unsupported authenticode data type\n");
      goto finish;
    }

    hlen = sec_dir_size;

    if (((uint32_t)(
            ((const union unaligned_32 *)(&(cert_hdr.length)))->una_s32)) !=
        hlen) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "cli_check_auth_header: MS13-098 violation detected, but "
                "continuing on to verify certificate\n");
    }

    at = sec_dir_offset + sizeof(cert_hdr);
    hlen -= sizeof(cert_hdr);

    ret = asn1_check_mscat((struct cl_engine *)(ctx->engine), map, at, hlen,
                           regions, nregions, ctx);

    if (CL_VERIFIED == ret) {

      goto finish;
    } else if (CL_VIRUS == ret) {

      goto finish;
    }

  } else {

    if (at < fsize) {
      hlen = fsize - at;
      do {
        regions[nregions].offset = (at);
        regions[nregions].size = (hlen);
        nregions++;
      } while (0);
    }
  }

  hashctx = cl_hash_init("sha1");
  if (((void *)0) == hashctx) {
    ret = CL_EMEM;
    goto finish;
  }

  for (i = 0; i < nregions; i++) {
    const uint8_t *hptr;
    if (0 == regions[i].size) {
      continue;
    }
    if (!(hptr = fmap_need_off_once(map, regions[i].offset, regions[i].size))) {
      break;
    }

    cl_update_hash(hashctx, hptr, regions[i].size);
  }

  if (i != nregions) {
    goto finish;
  }

  cl_finish_hash(hashctx, authsha1);
  hashctx = ((void *)0);

  if (cli_hm_scan(authsha1, 2, ((void *)0), ctx->engine->hm_fp,
                  CLI_HASH_SHA1) == CL_VIRUS) {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal(
              "cli_check_auth_header: PE file whitelisted by catalog file\n");
    ret = CL_CLEAN;
    goto finish;
  }

  ret = CL_EVERIFY;

finish:
  if (((void *)0) != hashctx) {
    cl_hash_destroy(hashctx);
  }

  if (((void *)0) != regions) {
    free(regions);
  }

  if (&_peinfo == peinfo) {
    cli_exe_info_destroy(peinfo);
  }
  return ret;
}
int cli_genhash_pe(cli_ctx *ctx, unsigned int class, int type,
                   stats_section_t *hashes) {
  unsigned int i;
  struct cli_exe_info _peinfo;
  struct cli_exe_info *peinfo = &_peinfo;

  unsigned char *hash, *hashset[CLI_HASH_AVAIL_TYPES];
  int genhash[CLI_HASH_AVAIL_TYPES];
  int hlen = 0;

  if (hashes) {
    hashes->sections = ((void *)0);

    if (class != CL_GENHASH_PE_CLASS_SECTION || type != 1) {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "`hashes` can only be populated with MD5 PE section data\n");
      return CL_EARG;
    }
  }

  if (class >= CL_GENHASH_PE_CLASS_LAST)
    return CL_EARG;

  cli_exe_info_init(peinfo, 0);

  if (cli_peheader(*ctx->fmap, peinfo, 0x0, ((void *)0)) != 0) {
    cli_exe_info_destroy(peinfo);
    return CL_EFORMAT;
  }

  cli_qsort(peinfo->sections, peinfo->nsections, sizeof(*(peinfo->sections)),
            sort_sects);

  memset(genhash, 0, sizeof(genhash));
  memset(hashset, 0, sizeof(hashset));
  switch (type) {
  case 1:
    genhash[CLI_HASH_MD5] = 1;
    hlen = hashlen[CLI_HASH_MD5];
    hash = hashset[CLI_HASH_MD5] = cli_calloc(hlen, sizeof(char));
    break;
  case 2:
    genhash[CLI_HASH_SHA1] = 1;
    hlen = hashlen[CLI_HASH_SHA1];
    hash = hashset[CLI_HASH_SHA1] = cli_calloc(hlen, sizeof(char));
    break;
  default:
    genhash[CLI_HASH_SHA256] = 1;
    hlen = hashlen[CLI_HASH_SHA256];
    hash = hashset[CLI_HASH_SHA256] = cli_calloc(hlen, sizeof(char));
    break;
  }

  if (!hash) {
    cli_errmsg("cli_genhash_pe: cli_malloc failed!\n");
    cli_exe_info_destroy(peinfo);
    return CL_EMEM;
  }

  if (hashes) {
    hashes->nsections = peinfo->nsections;
    hashes->sections =
        cli_calloc(peinfo->nsections, sizeof(struct cli_section_hash));

    if (!(hashes->sections)) {
      cli_exe_info_destroy(peinfo);
      free(hash);
      return CL_EMEM;
    }
  }

  if (class == CL_GENHASH_PE_CLASS_SECTION) {
    char *dstr;

    for (i = 0; i < peinfo->nsections; i++) {

      if (cli_hashsect(*ctx->fmap, &peinfo->sections[i], hashset, genhash,
                       genhash) == 1) {
        if (cli_debug_flag) {
          dstr = cli_str2hex((char *)hash, hlen);
          (!__builtin_expect(!!(cli_debug_flag), 0))
              ? (void)0
              : cli_dbgmsg_internal("Section{%u}: %u:%s\n", i,
                                    peinfo->sections[i].rsz,
                                    dstr ? (char *)dstr : "(NULL)");
          if (dstr != ((void *)0)) {
            free(dstr);
          }
        }
        if (hashes) {
          memcpy(hashes->sections[i].md5, hash,
                 sizeof(hashes->sections[i].md5));
          hashes->sections[i].len = peinfo->sections[i].rsz;
        }
      } else if (peinfo->sections[i].rsz) {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal(
                  "Section{%u}: failed to generate hash for section\n", i);
      } else {
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("Section{%u}: section contains no data\n", i);
      }
    }
  } else if (class == CL_GENHASH_PE_CLASS_IMPTBL) {
    char *dstr;
    uint32_t impsz = 0;
    int ret;

    ret = hash_imptbl(ctx, hashset, &impsz, genhash, peinfo);
    if (ret == CL_SUCCESS) {
      if (cli_debug_flag) {
        dstr = cli_str2hex((char *)hash, hlen);
        (!__builtin_expect(!!(cli_debug_flag), 0))
            ? (void)0
            : cli_dbgmsg_internal("Imphash: %s:%u\n",
                                  dstr ? (char *)dstr : "(NULL)", impsz);
        if (dstr != ((void *)0)) {
          free(dstr);
        }
      }
    } else {
      (!__builtin_expect(!!(cli_debug_flag), 0))
          ? (void)0
          : cli_dbgmsg_internal(
                "Imphash: failed to generate hash for import table (%d)\n",
                ret);
    }
  } else {
    (!__builtin_expect(!!(cli_debug_flag), 0))
        ? (void)0
        : cli_dbgmsg_internal("cli_genhash_pe: unknown pe genhash class: %u\n",
                              class);
  }

  free(hash);
  cli_exe_info_destroy(peinfo);
  return CL_SUCCESS;
}
