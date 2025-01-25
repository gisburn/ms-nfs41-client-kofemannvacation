/* NFSv4.1 client for Windows
 * Copyright (C) 2024-2025 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Roland Mainz <roland.mainz@nrubsig.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 */

#include <Windows.h>
#include <strsafe.h>

#include "nfs41_compound.h"
#include "nfs41_ops.h"
#include "nfs41_xdr.h"
#include "util.h"
#include "daemon_debug.h"
#include "rpc/rpc.h"

/* fixme: copy from nfs41_xdr.c */
static __inline int unexpected_op(uint32_t op, uint32_t expected)
{
    if (op == expected)
        return 0;

    eprintf("Op table mismatch. Got '%s' (%d), expected '%s' (%d).\n",
        nfs_opnum_to_string(op), op,
        nfs_opnum_to_string(expected), expected);
    return 1;
}

/*
 * OP_READ_PLUS
 */
bool_t encode_op_read_plus(
    XDR *xdr,
    nfs_argop4 *argop)
{
    nfs42_read_plus_args *args = (nfs42_read_plus_args *)argop->arg;

    if (unexpected_op(argop->op, OP_READ_PLUS))
        return FALSE;

    if (!xdr_stateid4(xdr, &args->stateid->stateid))
        return FALSE;

    if (!xdr_u_hyper(xdr, &args->offset))
        return FALSE;

    return xdr_u_int32_t(xdr, &args->count);
}

static bool_t decode_read_plus_res_ok(
    XDR *xdr,
    nfs42_read_plus_res_ok *res)
{
    unsigned char *data = res->data;
    int64_t data_bytesleft = res->data_len; /* must be |signed| */

    nfs42_read_plus_content *contents = NULL;

    if (!xdr_bool(xdr, &res->eof)) {
        DPRINTF(0, ("decode eof failed\n"));
        return FALSE;
    }

    if (!xdr_u_int32_t(xdr, &res->count)) {
        DPRINTF(0, ("decode count failed\n"));
        return FALSE;
    }

    /*
     * Note that |res->count==0| is a valid value for "READ_PLUS"
     * replies
     */
    if (res->count == 0) {
        res->data_len = 0L;
        return TRUE;
    }

    contents = _alloca(res->count * sizeof(nfs42_read_plus_content));

    uint32_t i, co;

    for (i = 0 ; i < res->count ; i++) {
        if (data_bytesleft < 0) {
            eprintf("decode_read_plus_res_ok: "
                "i=%d, data_bytesleft(=%lld) < 0\n",
                (int)i, (long long)data_bytesleft);
            break;
        }

        if (!xdr_u_int32_t(xdr, &co)) {
            DPRINTF(0, ("i=%d, decode co failed\n", (int)i));
            return FALSE;
        }
        contents[i].content = co;

        switch(co) {
            case NFS4_CONTENT_DATA:
//                DPRINTF(0, ("i=%d, 'NFS4_CONTENT_DATA' content\n", (int)i));
                if (!xdr_u_hyper(xdr, &contents[i].data.offset)) {
                    DPRINTF(0, ("i=%d, decoding 'offset' failed\n", (int)i));
                    return FALSE;
                }
                if (!xdr_u_int32_t(xdr, &contents[i].data.count)) {
                    DPRINTF(0, ("i=%d, decoding 'count' failed\n", (int)i));
                    return FALSE;
                }

                /* FIXME: what should we do with |data.offset| ? */

                EASSERT(contents[i].data.count <= data_bytesleft);
                /*
                 * If a buggy server erroneously sends more data then
                 * we requested we'll clamp this via |__min()| to
                 * avoid an buffer overflow (but will still get an
                 * RPC error later).
                 */
                contents[i].data.count = __min(data_bytesleft,
                    contents[i].data.count);

                contents[i].data.data = data;
                contents[i].data.data_len = contents[i].data.count;
                if (!xdr_opaque(xdr,
                    (char *)contents[i].data.data,
                    contents[i].data.data_len)) {
                    DPRINTF(0, ("i=%d, decoding 'bytes' failed\n", (int)i));
                    return FALSE;
                }
                data += contents[i].data.count;
                data_bytesleft -= contents[i].data.count;
                break;
            case NFS4_CONTENT_HOLE:
                DPRINTF(0, ("i=%d, 'NFS4_CONTENT_HOLE' content\n", (int)i));
                if (!xdr_u_hyper(xdr, &contents[i].hole.offset))
                    return FALSE;
                if (!xdr_u_hyper(xdr, &contents[i].hole.length))
                    return FALSE;

                /* FIXME: what should we do with |hole.offset| ? */

                /*
                 * NFSv4.2 "READ_PLUS" is required to return the
                 * whole hole even if |hole.length| is bigger than
                 * the requested size
                 */
                (void)memset(data, 0,
                    __min(data_bytesleft, contents[i].hole.length));
                data += contents[i].hole.length;
                data_bytesleft -= contents[i].hole.length;
            default:
                DPRINTF(0, ("decode_read_plus_res_ok: unknown co=%d\n", (int)co));
                return FALSE;
        }

        EASSERT((data - res->data) <= res->data_len);
    }

    EASSERT((data - res->data) < UINT_MAX);
    res->data_len = (uint32_t)(data - res->data);

    return TRUE;
}

bool_t decode_op_read_plus(
    XDR *xdr,
    nfs_resop4 *resop)
{
    nfs42_read_plus_res *res = (nfs42_read_plus_res *)resop->res;

    if (unexpected_op(resop->op, OP_READ_PLUS))
        return FALSE;

    if (!xdr_u_int32_t(xdr, &res->status))
        return FALSE;

    if (res->status == NFS4_OK)
        return decode_read_plus_res_ok(xdr, &res->resok4);

    return TRUE;
}

