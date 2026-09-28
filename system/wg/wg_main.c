/****************************************************************************
 * apps/system/wg/wg_main.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/* wg - configure and inspect a WireGuard network device.
 *
 * Follows the sub-command surface of wg(8) and its configuration file
 * format. All state lives in the kernel driver, reached through the
 * ioctls in include/nuttx/net/wireguard.h; this program keeps nothing
 * between invocations. The one asymmetry: the driver accepts a private
 * key but never returns it, so "saveconf" and "showconf" take the key
 * from the configuration file, and "set private-key" records it there.
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <nuttx/net/ioctl.h>
#include <nuttx/net/wireguard.h>

#include "wg_x25519.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define WG_IFNAME       "wg0"
#define WG_B64_LEN      44              /* base64 of 32 bytes, no NUL */
#define WG_LINE_MAX     256
#define WG_MAX_PEERS    64              /* Enumeration bound for show */

/****************************************************************************
 * Private Types
 ****************************************************************************/

/* A peer as read from a configuration file, before it is pushed */

struct wg_conf_peer_s
{
  bool valid;
  struct wg_peerreq_s req;
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: wg_b64_encode, wg_b64_decode
 ****************************************************************************/

static const char g_b64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void wg_b64_encode(FAR const uint8_t *in, FAR char *out)
{
  int i;
  int o = 0;

  for (i = 0; i < 30; i += 3)
    {
      uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                   in[i + 2];

      out[o++] = g_b64[(v >> 18) & 63];
      out[o++] = g_b64[(v >> 12) & 63];
      out[o++] = g_b64[(v >> 6) & 63];
      out[o++] = g_b64[v & 63];
    }

  /* 32 = 10 * 3 + 2: one final group with one pad character */

  {
    uint32_t v = ((uint32_t)in[30] << 16) | ((uint32_t)in[31] << 8);

    out[o++] = g_b64[(v >> 18) & 63];
    out[o++] = g_b64[(v >> 12) & 63];
    out[o++] = g_b64[(v >> 6) & 63];
    out[o++] = '=';
  }

  out[o] = '\0';
}

static int wg_b64_value(char c)
{
  FAR const char *p = strchr(g_b64, c);

  return (p == NULL || c == '\0') ? -1 : (int)(p - g_b64);
}

static bool wg_b64_decode(FAR const char *in, FAR uint8_t *out)
{
  int i;
  int o = 0;

  if (strlen(in) != WG_B64_LEN || in[WG_B64_LEN - 1] != '=')
    {
      return false;
    }

  for (i = 0; i < 40; i += 4)
    {
      int a = wg_b64_value(in[i]);
      int b = wg_b64_value(in[i + 1]);
      int c = wg_b64_value(in[i + 2]);
      int d = wg_b64_value(in[i + 3]);
      uint32_t v;

      if (a < 0 || b < 0 || c < 0 || d < 0)
        {
          return false;
        }

      v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) |
          (uint32_t)d;
      out[o++] = (uint8_t)(v >> 16);
      out[o++] = (uint8_t)(v >> 8);
      out[o++] = (uint8_t)v;
    }

  {
    int a = wg_b64_value(in[40]);
    int b = wg_b64_value(in[41]);
    int c = wg_b64_value(in[42]);
    uint32_t v;

    if (a < 0 || b < 0 || c < 0 || (c & 3) != 0)
      {
        return false;
      }

    v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6);
    out[o++] = (uint8_t)(v >> 16);
    out[o++] = (uint8_t)(v >> 8);
  }

  return true;
}

/****************************************************************************
 * Name: wg_random_key
 *
 * Description:
 *   32 bytes from /dev/urandom, clamped as a Curve25519 scalar. The
 *   driver refuses to build against a constant-seeded PRNG backend, so
 *   /dev/urandom is a real source in any configuration that has wg0.
 *
 ****************************************************************************/

static bool wg_random_key(FAR uint8_t *key)
{
  size_t total = 0;
  int fd;

  fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    {
      return false;
    }

  while (total < WG_KEY_LEN)
    {
      ssize_t n = read(fd, key + total, WG_KEY_LEN - total);

      if (n <= 0)
        {
          break;
        }

      total += (size_t)n;
    }

  close(fd);
  if (total != WG_KEY_LEN)
    {
      return false;
    }

  key[0] &= 248;
  key[31] = (key[31] & 127) | 64;
  return true;
}

/****************************************************************************
 * Name: wg_derive_public
 ****************************************************************************/

static bool wg_derive_public(FAR uint8_t *pub, FAR const uint8_t *priv)
{
  return x25519(pub, priv, X25519_BASE_POINT, 1) == 0;
}

/****************************************************************************
 * Name: wg_open, wg_ioctl
 *
 * Description:
 *   The ioctls travel over any AF_INET socket; the request names the
 *   interface.
 *
 ****************************************************************************/

static int wg_open(void)
{
  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (fd < 0)
    {
      fprintf(stderr, "wg: socket: %s\n", strerror(errno));
    }

  return fd;
}

static int wg_ioctl(int fd, int cmd, FAR void *req)
{
  if (ioctl(fd, cmd, (unsigned long)(uintptr_t)req) < 0)
    {
      return -errno;
    }

  return OK;
}

/****************************************************************************
 * Name: wg_get_if, wg_get_peer
 ****************************************************************************/

static int wg_get_if(int fd, FAR struct wg_ifreq_s *ifr)
{
  memset(ifr, 0, sizeof(*ifr));
  strlcpy(ifr->ifname, WG_IFNAME, IFNAMSIZ);
  return wg_ioctl(fd, SIOCGWGIF, ifr);
}

static int wg_get_peer(int fd, int index, FAR struct wg_peerreq_s *req)
{
  memset(req, 0, sizeof(*req));
  strlcpy(req->ifname, WG_IFNAME, IFNAMSIZ);
  req->index = index;
  return wg_ioctl(fd, SIOCGWGPEER, req);
}

/****************************************************************************
 * Name: wg_parse_endpoint, wg_parse_aip
 ****************************************************************************/

static bool wg_parse_endpoint(FAR const char *s, FAR struct sockaddr_in *sa)
{
  char host[INET_ADDRSTRLEN];
  FAR const char *colon = strrchr(s, ':');
  long port;

  if (colon == NULL || (size_t)(colon - s) >= sizeof(host))
    {
      return false;
    }

  memcpy(host, s, colon - s);
  host[colon - s] = '\0';
  port = strtol(colon + 1, NULL, 10);
  if (port <= 0 || port > 65535)
    {
      return false;
    }

  memset(sa, 0, sizeof(*sa));
  sa->sin_family = AF_INET;
  sa->sin_port = htons((uint16_t)port);
  return inet_pton(AF_INET, host, &sa->sin_addr) == 1;
}

static bool wg_parse_aip(FAR const char *s, FAR struct wg_aip_s *aip)
{
  char host[INET_ADDRSTRLEN];
  FAR const char *slash = strchr(s, '/');
  long cidr = 32;

  if (slash != NULL)
    {
      if ((size_t)(slash - s) >= sizeof(host))
        {
          return false;
        }

      memcpy(host, s, slash - s);
      host[slash - s] = '\0';
      cidr = strtol(slash + 1, NULL, 10);
      if (cidr < 0 || cidr > 32)
        {
          return false;
        }
    }
  else
    {
      strlcpy(host, s, sizeof(host));
    }

  memset(aip, 0, sizeof(*aip));
  aip->cidr = (uint8_t)cidr;
  return inet_pton(AF_INET, host, &aip->addr) == 1;
}

/* "a/32,b/24" -> aips[], returns count or -1 */

static int wg_parse_aips(FAR char *list, FAR struct wg_aip_s *aips)
{
  FAR char *save;
  FAR char *tok;
  int n = 0;

  for (tok = strtok_r(list, ",", &save); tok != NULL;
       tok = strtok_r(NULL, ",", &save))
    {
      while (*tok == ' ')
        {
          tok++;
        }

      if (n >= WG_MAX_AIPS || !wg_parse_aip(tok, &aips[n]))
        {
          return -1;
        }

      n++;
    }

  return n;
}

/****************************************************************************
 * Name: wg_file_private_key
 *
 * Description:
 *   The PrivateKey line of a configuration file, if the file exists and
 *   has one.
 *
 ****************************************************************************/

static bool wg_file_private_key(FAR const char *path, FAR char *key)
{
  char line[WG_LINE_MAX];
  FAR FILE *f;
  bool found = false;

  f = fopen(path, "r");
  if (f == NULL)
    {
      return false;
    }

  while (fgets(line, sizeof(line), f) != NULL)
    {
      FAR char *p = line;
      FAR char *eq;

      while (*p == ' ' || *p == '\t')
        {
          p++;
        }

      if (strncasecmp(p, "PrivateKey", 10) != 0)
        {
          continue;
        }

      eq = strchr(p, '=');
      if (eq == NULL)
        {
          continue;
        }

      eq++;
      while (*eq == ' ' || *eq == '\t')
        {
          eq++;
        }

      eq[strcspn(eq, " \t\r\n")] = '\0';
      if (strlen(eq) == WG_B64_LEN)
        {
          strlcpy(key, eq, WG_B64_LEN + 1);
          found = true;
          break;
        }
    }

  fclose(f);
  return found;
}

/****************************************************************************
 * Name: wg_write_conf
 *
 * Description:
 *   Write the device's configuration in wg(8) format. The private key is
 *   whatever the caller knows (from the file or the command line); when
 *   unknown it is written as a placeholder so the file is still readable
 *   by a human but not loadable by setconf.
 *
 ****************************************************************************/

static int wg_write_conf(int fd, FAR FILE *out, FAR const char *privkey)
{
  struct wg_ifreq_s ifr;
  struct wg_peerreq_s peer;
  char b64[WG_B64_LEN + 1];
  char addr[INET_ADDRSTRLEN];
  int ret;
  int i;
  int j;

  ret = wg_get_if(fd, &ifr);
  if (ret < 0)
    {
      return ret;
    }

  fprintf(out, "[Interface]\n");
  fprintf(out, "PrivateKey = %s\n", privkey != NULL ? privkey : "(hidden)");
  fprintf(out, "ListenPort = %u\n", ifr.listen_port);
  if ((ifr.flags & WG_IF_HAS_ADDR) && ifr.addr.s_addr != 0)
    {
      uint32_t m = ntohl(ifr.netmask.s_addr);
      int cidr = 0;

      while (m & 0x80000000u)
        {
          cidr++;
          m <<= 1;
        }

      inet_ntop(AF_INET, &ifr.addr, addr, sizeof(addr));
      fprintf(out, "Address = %s/%d\n", addr, cidr);
    }

  for (i = 0; i < ifr.npeers; i++)
    {
      if (wg_get_peer(fd, i, &peer) < 0)
        {
          break;
        }

      wg_b64_encode(peer.public_key, b64);
      fprintf(out, "\n[Peer]\n");
      fprintf(out, "PublicKey = %s\n", b64);

      if (peer.flags & WG_PEER_HAS_AIPS)
        {
          fprintf(out, "AllowedIPs = ");
          for (j = 0; j < peer.naips; j++)
            {
              inet_ntop(AF_INET, &peer.aips[j].addr, addr, sizeof(addr));
              fprintf(out, "%s%s/%u", j > 0 ? ", " : "", addr,
                      peer.aips[j].cidr);
            }

          fprintf(out, "\n");
        }

      if (peer.flags & WG_PEER_HAS_ENDPOINT)
        {
          inet_ntop(AF_INET, &peer.endpoint.sin_addr, addr, sizeof(addr));
          fprintf(out, "Endpoint = %s:%u\n", addr,
                  ntohs(peer.endpoint.sin_port));
        }

      if (peer.keepalive > 0)
        {
          fprintf(out, "PersistentKeepalive = %u\n", peer.keepalive);
        }
    }

  return OK;
}

/****************************************************************************
 * Name: wg_set_if
 ****************************************************************************/

static int wg_set_if(int fd, FAR struct wg_ifreq_s *ifr)
{
  strlcpy(ifr->ifname, WG_IFNAME, IFNAMSIZ);
  return wg_ioctl(fd, SIOCSWGIF, ifr);
}

/****************************************************************************
 * Name: wg_record_private_key
 *
 * Description:
 *   Keep the private key in the configuration file so that a later
 *   saveconf can write a loadable file. Rewrites the PrivateKey line in
 *   place, or creates a minimal file.
 *
 ****************************************************************************/

/****************************************************************************
 * Name: wg_open_temp
 *
 * Description:
 *   Stage each writer into its own exclusively created, mode-0600 file.
 *
 ****************************************************************************/

static FAR FILE *wg_open_temp(FAR char *buf, size_t buflen,
                              FAR const char *path)
{
  FAR FILE *out;
  int fd;
  int ret = snprintf(buf, buflen, "%s.tmp.XXXXXX", path);

  if (ret < 0 || (size_t)ret >= buflen)
    {
      fprintf(stderr, "wg: temporary path is too long\n");
      return NULL;
    }

  fd = mkstemp(buf);
  if (fd < 0)
    {
      return NULL;
    }

  out = fdopen(fd, "w");
  if (out == NULL)
    {
      close(fd);
      unlink(buf);
    }

  return out;
}

/****************************************************************************
 * Name: wg_replace_file
 *
 * Description:
 *   Preserve the old content before rename: the NuttX VFS can unlink the
 *   destination even when rename subsequently fails. An exclusive backup
 *   also serializes publishers. A failed publish leaves both files for
 *   explicit recovery and blocks further publishers. This is not a power
 *   loss durability guarantee.
 *
 * Returned Value:
 *   Zero on success, -1 on failure.
 *
 ****************************************************************************/

static int wg_replace_file(FAR const char *tmp, FAR const char *path)
{
  char backup[160];
  char buf[128];
  FAR FILE *in;
  FAR FILE *out;
  size_t n;
  int fd;
  int ret;
  bool failed = false;
  bool existed;

  ret = snprintf(backup, sizeof(backup), "%s.bak", path);
  if (ret < 0 || (size_t)ret >= sizeof(backup))
    {
      fprintf(stderr, "wg: backup path is too long\n");
      unlink(tmp);
      return -1;
    }

  fd = open(backup, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    {
      fprintf(stderr, "wg: cannot reserve '%s': %s; check for an active "
              "writer or recover a previous failed save\n",
              backup, strerror(errno));
      unlink(tmp);
      return -1;
    }

  out = fdopen(fd, "w");
  if (out == NULL)
    {
      close(fd);
      unlink(backup);
      unlink(tmp);
      return -1;
    }

  in = fopen(path, "r");
  existed = in != NULL;
  if (in == NULL)
    {
      failed = errno != ENOENT;
    }
  else
    {
      while ((n = fread(buf, 1, sizeof(buf), in)) != 0)
        {
          if (fwrite(buf, 1, n, out) != n)
            {
              failed = true;
              break;
            }
        }

      failed |= ferror(in) != 0;
      failed |= fclose(in) != 0;
    }

  memset(buf, 0, sizeof(buf));
  failed |= fclose(out) != 0;
  if (failed)
    {
      fprintf(stderr, "wg: cannot back up '%s'; save aborted\n", path);
      unlink(backup);
      unlink(tmp);
      return -1;
    }

  if (rename(tmp, path) != 0)
    {
      fprintf(stderr, "wg: cannot publish '%s': %s; new content: '%s'; "
              "recovery file: '%s' (%s). Recover before saving again\n",
              path, strerror(errno), tmp, backup,
              existed ? "previous configuration" : "no previous file");
      return -1;
    }

  if (unlink(backup) != 0)
    {
      fprintf(stderr, "wg: '%s' saved but cannot remove '%s': %s; "
              "remove the backup before saving again\n",
              path, backup, strerror(errno));
      return -1;
    }

  return 0;
}

/****************************************************************************
 * Name: wg_record_private_key
 *
 * Description:
 *   Store key as the PrivateKey of path, keeping the rest of the file. The
 *   driver never returns the private key, so this file is the only copy;
 *   every failure has to reach the caller.
 *
 * Returned Value:
 *   Zero on success, -1 on failure (a failed publish retains a backup).
 *
 ****************************************************************************/

static int wg_record_private_key(FAR const char *path,
                                 FAR const char *key)
{
  char line[WG_LINE_MAX];
  FAR FILE *in;
  FAR FILE *out;
  char tmp[128];
  bool written = false;

  out = wg_open_temp(tmp, sizeof(tmp), path);
  if (out == NULL)
    {
      fprintf(stderr, "wg: cannot write '%s': %s\n", tmp, strerror(errno));
      return -1;
    }

  in = fopen(path, "r");
  if (in != NULL)
    {
      while (fgets(line, sizeof(line), in) != NULL)
        {
          FAR char *p = line;

          while (*p == ' ' || *p == '\t')
            {
              p++;
            }

          if (strncasecmp(p, "PrivateKey", 10) == 0)
            {
              if (!written)
                {
                  fprintf(out, "PrivateKey = %s\n", key);
                  written = true;
                }
            }
          else
            {
              fputs(line, out);
              if (!written && strncasecmp(p, "[Interface]", 11) == 0)
                {
                  fprintf(out, "PrivateKey = %s\n", key);
                  written = true;
                }
            }
        }

      if (ferror(in) != 0)
        {
          fclose(in);
          fclose(out);
          unlink(tmp);
          fprintf(stderr, "wg: cannot read '%s'; save aborted\n", path);
          return -1;
        }

      fclose(in);
    }
  else if (errno != ENOENT)
    {
      fclose(out);
      unlink(tmp);
      fprintf(stderr, "wg: cannot read '%s'; save aborted\n", path);
      return -1;
    }

  if (!written)
    {
      fprintf(out, "[Interface]\nPrivateKey = %s\n", key);
    }

  if (ferror(out) != 0)
    {
      fclose(out);
      unlink(tmp);
      fprintf(stderr, "wg: cannot write '%s'\n", tmp);
      return -1;
    }

  if (fclose(out) != 0)
    {
      unlink(tmp);
      fprintf(stderr, "wg: cannot write '%s': %s\n", tmp, strerror(errno));
      return -1;
    }

  return wg_replace_file(tmp, path);
}

/****************************************************************************
 * Name: wg_cmd_show
 ****************************************************************************/

static int wg_cmd_show(int fd)
{
  struct wg_ifreq_s ifr;
  struct wg_peerreq_s peer;
  char b64[WG_B64_LEN + 1];
  char addr[INET_ADDRSTRLEN];
  int ret;
  int i;

  ret = wg_get_if(fd, &ifr);
  if (ret < 0)
    {
      fprintf(stderr, "wg: %s: %s\n", WG_IFNAME, strerror(-ret));
      return 1;
    }

  printf("interface: %s\n", WG_IFNAME);
  if (ifr.flags & WG_IF_HAS_PUBLIC_KEY)
    {
      wg_b64_encode(ifr.public_key, b64);
      printf("  public key: %s\n", b64);
    }
  else
    {
      printf("  public key: (none)\n");
    }

  printf("  listening port: %u\n", ifr.listen_port);
  if (!(ifr.flags & WG_IF_UP))
    {
      printf("  status: down\n");
    }

  for (i = 0; i < ifr.npeers; i++)
    {
      if (wg_get_peer(fd, i, &peer) < 0)
        {
          break;
        }

      wg_b64_encode(peer.public_key, b64);
      printf("peer: %s\n", b64);
      if (peer.flags & WG_PEER_HAS_ENDPOINT)
        {
          inet_ntop(AF_INET, &peer.endpoint.sin_addr, addr, sizeof(addr));
          printf("  endpoint: %s:%u\n", addr, ntohs(peer.endpoint.sin_port));
        }

      if (peer.flags & WG_PEER_HANDSHAKED)
        {
          printf("  latest handshake: %lu seconds ago\n",
                 (unsigned long)(peer.last_handshake / 1000));
        }
      else
        {
          printf("  latest handshake: (never)\n");
        }

      printf("  transfer: %llu B received, %llu B sent\n",
             (unsigned long long)peer.rx_bytes,
             (unsigned long long)peer.tx_bytes);
      if (peer.keepalive > 0)
        {
          printf("  persistent keepalive: every %u seconds\n",
                 peer.keepalive);
        }
    }

  return 0;
}

/****************************************************************************
 * Name: wg_cmd_updown
 ****************************************************************************/

static int wg_cmd_updown(int fd, bool up)
{
  struct wg_ifreq_s ifr;
  int ret;

  memset(&ifr, 0, sizeof(ifr));
  ifr.flags = up ? WG_IF_UP : WG_IF_DOWN;
  ret = wg_set_if(fd, &ifr);
  if (ret < 0)
    {
      if (ret == -EINVAL && up)
        {
          fprintf(stderr, "wg: no private key: run \"wg set private-key\" "
                  "or \"wg setconf\" first\n");
        }
      else
        {
          fprintf(stderr, "wg: %s: %s\n", up ? "up" : "down",
                  strerror(-ret));
        }

      return 1;
    }

  if (up)
    {
      wg_get_if(fd, &ifr);
      printf("%s is up (listen port %u)\n", WG_IFNAME, ifr.listen_port);
    }

  return 0;
}

/****************************************************************************
 * Name: wg_cmd_set
 *
 * Description:
 *   wg set private-key <key> | listen-port <n> | address <a/n> |
 *          peer <pub> [remove] [endpoint <a:p>] [allowed-ips <a/n,...>]
 *                     [persistent-keepalive <s>] [preshared-key <key>]
 *
 ****************************************************************************/

static int wg_cmd_set(int fd, int argc, FAR char *argv[])
{
  struct wg_ifreq_s ifr;
  struct wg_peerreq_s peer;
  int ret;
  int i;

  if (argc < 4)
    {
      fprintf(stderr, "wg: set needs an item\n");
      return 1;
    }

  memset(&ifr, 0, sizeof(ifr));

  if (strcmp(argv[2], "private-key") == 0)
    {
      if (!wg_b64_decode(argv[3], ifr.private_key))
        {
          fprintf(stderr, "wg: not a valid base64 key\n");
          return 1;
        }

      ifr.flags = WG_IF_HAS_PRIVATE_KEY;
      ret = wg_set_if(fd, &ifr);
      memset(ifr.private_key, 0, sizeof(ifr.private_key));
      if (ret == OK &&
          wg_record_private_key(CONFIG_SYSTEM_WG_CONFIG_PATH, argv[3]) < 0)
        {
          /* The device took the key but it is not on storage. Saying
           * nothing here would lose it silently at the next restart.
           */

          fprintf(stderr, "wg: the device now uses the new key, but it "
                          "could not be saved to %s; it will be lost on "
                          "restart\n", CONFIG_SYSTEM_WG_CONFIG_PATH);
          return 1;
        }
    }
  else if (strcmp(argv[2], "listen-port") == 0)
    {
      ifr.flags = WG_IF_HAS_LISTEN_PORT;
      ifr.listen_port = (uint16_t)strtoul(argv[3], NULL, 10);
      ret = wg_set_if(fd, &ifr);
    }
  else if (strcmp(argv[2], "address") == 0)
    {
      struct wg_aip_s a;

      if (!wg_parse_aip(argv[3], &a))
        {
          fprintf(stderr, "wg: bad address\n");
          return 1;
        }

      ifr.flags = WG_IF_HAS_ADDR;
      ifr.addr = a.addr;
      ifr.netmask.s_addr = a.cidr == 0 ? 0 :
                           htonl(0xffffffffu << (32 - a.cidr));
      ret = wg_set_if(fd, &ifr);
    }
  else if (strcmp(argv[2], "peer") == 0)
    {
      memset(&peer, 0, sizeof(peer));
      strlcpy(peer.ifname, WG_IFNAME, IFNAMSIZ);
      if (!wg_b64_decode(argv[3], peer.public_key))
        {
          fprintf(stderr, "wg: not a valid base64 key\n");
          return 1;
        }

      if (argc >= 5 && strcmp(argv[4], "remove") == 0)
        {
          ret = wg_ioctl(fd, SIOCDWGPEER, &peer);
          goto done;
        }

      for (i = 4; i + 1 < argc; i += 2)
        {
          if (strcmp(argv[i], "endpoint") == 0)
            {
              if (!wg_parse_endpoint(argv[i + 1], &peer.endpoint))
                {
                  fprintf(stderr, "wg: bad endpoint\n");
                  return 1;
                }

              peer.flags |= WG_PEER_HAS_ENDPOINT;
            }
          else if (strcmp(argv[i], "allowed-ips") == 0)
            {
              int n = wg_parse_aips(argv[i + 1], peer.aips);

              if (n < 0)
                {
                  fprintf(stderr, "wg: bad allowed-ips\n");
                  return 1;
                }

              peer.naips = (uint8_t)n;
              peer.flags |= WG_PEER_HAS_AIPS | WG_PEER_REPLACE_AIPS;
            }
          else if (strcmp(argv[i], "persistent-keepalive") == 0)
            {
              peer.keepalive = strcmp(argv[i + 1], "off") == 0 ? 0 :
                               (uint16_t)strtoul(argv[i + 1], NULL, 10);
              peer.flags |= WG_PEER_HAS_KEEPALIVE;
            }
          else if (strcmp(argv[i], "preshared-key") == 0)
            {
              if (!wg_b64_decode(argv[i + 1], peer.preshared_key))
                {
                  fprintf(stderr, "wg: not a valid base64 key\n");
                  return 1;
                }

              peer.flags |= WG_PEER_HAS_PSK;
            }
          else
            {
              fprintf(stderr, "wg: unknown peer option '%s'\n", argv[i]);
              return 1;
            }
        }

      ret = wg_ioctl(fd, SIOCSWGPEER, &peer);
      memset(peer.preshared_key, 0, sizeof(peer.preshared_key));
    }
  else
    {
      fprintf(stderr, "wg: unknown item '%s'\n", argv[2]);
      return 1;
    }

done:
  if (ret < 0)
    {
      fprintf(stderr, "wg: set %s: %s\n", argv[2],
              ret == -EBUSY ? "interface must be down" :
              ret == -EEXIST ? "allowed-ips overlap another peer" :
              ret == -ENOKEY ? "set the private key first" :
              strerror(-ret));
      return 1;
    }

  return 0;
}

/****************************************************************************
 * Name: wg_cmd_setconf
 *
 * Description:
 *   Load a wg(8) / wg-quick style file: [Interface] PrivateKey,
 *   ListenPort, Address; [Peer] PublicKey, PresharedKey, AllowedIPs,
 *   Endpoint, PersistentKeepalive. Applied only after the whole file has
 *   parsed, so a bad line leaves the device untouched.
 *
 ****************************************************************************/

static int wg_cmd_setconf(int fd, FAR const char *path)
{
  struct wg_ifreq_s ifr;
  struct wg_conf_peer_s peers[CONFIG_NET_WIREGUARD_MAX_PEERS];
  FAR struct wg_conf_peer_s *cur = NULL;
  char line[WG_LINE_MAX];
  FAR FILE *f;
  int npeers = 0;
  int lineno = 0;
  int ret;
  int i;

  f = fopen(path, "r");
  if (f == NULL)
    {
      fprintf(stderr, "wg: cannot open %s: %s\n", path, strerror(errno));
      return 1;
    }

  memset(&ifr, 0, sizeof(ifr));
  memset(peers, 0, sizeof(peers));

  while (fgets(line, sizeof(line), f) != NULL)
    {
      FAR char *key = line;
      FAR char *val;
      FAR char *eq;

      lineno++;
      key[strcspn(key, "\r\n")] = '\0';
      while (*key == ' ' || *key == '\t')
        {
          key++;
        }

      if (*key == '\0' || *key == '#')
        {
          continue;
        }

      if (strcasecmp(key, "[Interface]") == 0)
        {
          cur = NULL;
          continue;
        }

      if (strcasecmp(key, "[Peer]") == 0)
        {
          if (npeers >= CONFIG_NET_WIREGUARD_MAX_PEERS)
            {
              fprintf(stderr, "wg: %s:%d: too many peers\n", path, lineno);
              goto fail;
            }

          cur = &peers[npeers++];
          cur->valid = true;
          strlcpy(cur->req.ifname, WG_IFNAME, IFNAMSIZ);
          continue;
        }

      eq = strchr(key, '=');
      if (eq == NULL)
        {
          fprintf(stderr, "wg: %s:%d: expected key = value\n", path,
                  lineno);
          goto fail;
        }

      val = eq + 1;
      *eq = '\0';
      key[strcspn(key, " \t")] = '\0';
      while (*val == ' ' || *val == '\t')
        {
          val++;
        }

      if (cur == NULL)
        {
          if (strcasecmp(key, "PrivateKey") == 0)
            {
              if (!wg_b64_decode(val, ifr.private_key))
                {
                  goto badvalue;
                }

              ifr.flags |= WG_IF_HAS_PRIVATE_KEY;
            }
          else if (strcasecmp(key, "ListenPort") == 0)
            {
              ifr.listen_port = (uint16_t)strtoul(val, NULL, 10);
              ifr.flags |= WG_IF_HAS_LISTEN_PORT;
            }
          else if (strcasecmp(key, "Address") == 0)
            {
              struct wg_aip_s a;

              if (!wg_parse_aip(val, &a))
                {
                  goto badvalue;
                }

              ifr.addr = a.addr;
              ifr.netmask.s_addr = a.cidr == 0 ? 0 :
                                   htonl(0xffffffffu << (32 - a.cidr));
              ifr.flags |= WG_IF_HAS_ADDR;
            }

          /* DNS, MTU, PostUp and friends are wg-quick's business */
        }
      else
        {
          if (strcasecmp(key, "PublicKey") == 0)
            {
              if (!wg_b64_decode(val, cur->req.public_key))
                {
                  goto badvalue;
                }
            }
          else if (strcasecmp(key, "PresharedKey") == 0)
            {
              if (!wg_b64_decode(val, cur->req.preshared_key))
                {
                  goto badvalue;
                }

              cur->req.flags |= WG_PEER_HAS_PSK;
            }
          else if (strcasecmp(key, "AllowedIPs") == 0)
            {
              int n = wg_parse_aips(val, cur->req.aips);

              if (n < 0)
                {
                  goto badvalue;
                }

              cur->req.naips = (uint8_t)n;
              cur->req.flags |= WG_PEER_HAS_AIPS | WG_PEER_REPLACE_AIPS;
            }
          else if (strcasecmp(key, "Endpoint") == 0)
            {
              if (!wg_parse_endpoint(val, &cur->req.endpoint))
                {
                  goto badvalue;
                }

              cur->req.flags |= WG_PEER_HAS_ENDPOINT;
            }
          else if (strcasecmp(key, "PersistentKeepalive") == 0)
            {
              cur->req.keepalive = strcasecmp(val, "off") == 0 ? 0 :
                                   (uint16_t)strtoul(val, NULL, 10);
              cur->req.flags |= WG_PEER_HAS_KEEPALIVE;
            }
        }

      continue;

badvalue:
      fprintf(stderr, "wg: %s:%d: bad value for %s\n", path, lineno, key);
      goto fail;
    }

  fclose(f);
  f = NULL;

  /* Apply: interface first (the key must exist before peers), then the
   * peers. Existing peers are removed so the file is the whole truth.
   */

  ret = wg_set_if(fd, &ifr);
  if (ret < 0)
    {
      fprintf(stderr, "wg: setconf: %s\n",
              ret == -EBUSY ? "interface must be down" : strerror(-ret));
      goto fail;
    }

  {
    struct wg_ifreq_s cur_if;
    struct wg_peerreq_s old;

    if (wg_get_if(fd, &cur_if) == OK)
      {
        while (cur_if.npeers > 0 && wg_get_peer(fd, 0, &old) == OK)
          {
            if (wg_ioctl(fd, SIOCDWGPEER, &old) < 0)
              {
                break;
              }

            cur_if.npeers--;
          }
      }
  }

  for (i = 0; i < npeers; i++)
    {
      ret = wg_ioctl(fd, SIOCSWGPEER, &peers[i].req);
      if (ret < 0)
        {
          fprintf(stderr, "wg: setconf: peer %d: %s\n", i + 1,
                  ret == -EEXIST ? "allowed-ips overlap another peer" :
                  strerror(-ret));
          goto fail;
        }
    }

  memset(&ifr, 0, sizeof(ifr));
  memset(peers, 0, sizeof(peers));
  return 0;

fail:
  if (f != NULL)
    {
      fclose(f);
    }

  memset(&ifr, 0, sizeof(ifr));
  memset(peers, 0, sizeof(peers));
  return 1;
}

/****************************************************************************
 * Name: wg_cmd_saveconf
 ****************************************************************************/

static int wg_cmd_saveconf(int fd, FAR const char *path)
{
  char priv[WG_B64_LEN + 1];
  char tmp[128];
  FAR FILE *f;
  bool have_priv;
  int ret;

  have_priv = wg_file_private_key(path, priv);
  if (!have_priv)
    {
      fprintf(stderr, "wg: no private key known for %s; the driver does "
              "not return it. Use \"wg set private-key\" (which records "
              "it) or write the file by hand\n", path);
      return 1;
    }

  f = wg_open_temp(tmp, sizeof(tmp), path);
  if (f == NULL)
    {
      memset(priv, 0, sizeof(priv));
      fprintf(stderr, "wg: cannot write %s: %s\n", tmp, strerror(errno));
      return 1;
    }

  ret = wg_write_conf(fd, f, priv);
  memset(priv, 0, sizeof(priv));
  if (fclose(f) != 0 || ret < 0)
    {
      unlink(tmp);
      fprintf(stderr, "wg: could not write '%s'\n", path);
      return 1;
    }

  if (wg_replace_file(tmp, path) < 0)
    {
      return 1;
    }

  printf("saved to %s\n", path);
  return 0;
}

/****************************************************************************
 * Name: wg_usage
 ****************************************************************************/

static void wg_usage(void)
{
  fprintf(stderr,
    "usage: wg [up|down|show|showconf|setconf|saveconf|genkey|pubkey|set]\n"
    "\n"
    "  up                      bring wg0 up (default if no argument)\n"
    "  down                    take wg0 down\n"
    "  show                    print interface and peer status\n"
    "  showconf                print the configuration in wg(8) format\n"
    "  saveconf [file]         write it to a file so it survives a reboot\n"
    "  setconf <file>          load a wg(8) format configuration file\n"
    "  genkey                  print a new private key\n"
    "  pubkey                  read a private key from stdin and print\n"
    "                          the matching public key\n"
    "\n"
    "  set private-key <key>\n"
    "  set listen-port <port>\n"
    "  set address <addr>/<prefix>\n"
    "  set peer <public-key> [endpoint <addr:port>]\n"
    "                         [allowed-ips <addr>/<prefix>[,...]]\n"
    "                         [persistent-keepalive <seconds>|off]\n"
    "                         [preshared-key <key>]\n"
    "  set peer <public-key> remove\n"
    "\n"
    "The private key, listen port and setconf are accepted only while wg0\n"
    "is down. The default file is " CONFIG_SYSTEM_WG_CONFIG_PATH ".\n");
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  FAR const char *cmd = argc >= 2 ? argv[1] : "up";
  int fd;
  int ret;

  if (strcmp(cmd, "genkey") == 0)
    {
      uint8_t key[WG_KEY_LEN];
      char b64[WG_B64_LEN + 1];

      if (!wg_random_key(key))
        {
          fprintf(stderr, "wg: /dev/urandom is not usable\n");
          return 1;
        }

      wg_b64_encode(key, b64);
      memset(key, 0, sizeof(key));
      printf("%s\n", b64);
      return 0;
    }

  if (strcmp(cmd, "pubkey") == 0)
    {
      char in[WG_B64_LEN + 4];
      uint8_t priv[WG_KEY_LEN];
      uint8_t pub[WG_KEY_LEN];
      char b64[WG_B64_LEN + 1];
      FAR const char *src;

      /* Like wg(8), from stdin, so the key stays out of the history */

      if (argc >= 3)
        {
          src = argv[2];
        }
      else if (fgets(in, sizeof(in), stdin) != NULL)
        {
          in[strcspn(in, " \t\r\n")] = '\0';
          src = in;
        }
      else
        {
          src = "";
        }

      if (!wg_b64_decode(src, priv) || !wg_derive_public(pub, priv))
        {
          fprintf(stderr, "wg: not a valid private key\n");
          return 1;
        }

      memset(priv, 0, sizeof(priv));
      wg_b64_encode(pub, b64);
      printf("%s\n", b64);
      return 0;
    }

  if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0)
    {
      wg_usage();
      return 0;
    }

  fd = wg_open();
  if (fd < 0)
    {
      return 1;
    }

  if (strcmp(cmd, "up") == 0)
    {
      ret = wg_cmd_updown(fd, true);
    }
  else if (strcmp(cmd, "down") == 0)
    {
      ret = wg_cmd_updown(fd, false);
    }
  else if (strcmp(cmd, "show") == 0)
    {
      ret = wg_cmd_show(fd);
    }
  else if (strcmp(cmd, "showconf") == 0)
    {
      char priv[WG_B64_LEN + 1];
      bool have = wg_file_private_key(CONFIG_SYSTEM_WG_CONFIG_PATH, priv);

      ret = wg_write_conf(fd, stdout, have ? priv : NULL) < 0 ? 1 : 0;
      memset(priv, 0, sizeof(priv));
    }
  else if (strcmp(cmd, "setconf") == 0)
    {
      ret = wg_cmd_setconf(fd, argc >= 3 ? argv[2] :
                           CONFIG_SYSTEM_WG_CONFIG_PATH);
    }
  else if (strcmp(cmd, "saveconf") == 0)
    {
      ret = wg_cmd_saveconf(fd, argc >= 3 ? argv[2] :
                            CONFIG_SYSTEM_WG_CONFIG_PATH);
    }
  else if (strcmp(cmd, "set") == 0)
    {
      ret = wg_cmd_set(fd, argc, argv);
    }
  else
    {
      wg_usage();
      ret = 1;
    }

  close(fd);
  return ret;
}
