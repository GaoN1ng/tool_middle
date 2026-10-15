/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* RSA Functions - see main program below */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "rsa_2048.h"

/* generate an RSA key pair */
void RSA_2048_KEY_PAIR(csprng *RNG, sign32 e, rsa_private_key_2048 *PRIV, rsa_public_key_2048 *PUB, octet *P, octet* Q)
{
    /* IEEE1363 A16.11/A16.12 more or less */
    BIG_512_60 t[HFLEN_2048], p1[HFLEN_2048], q1[HFLEN_2048];

    if (RNG != NULL)
    {
        for (;;)
        {
            for (;;)
            {

                FF_2048_random(PRIV->p, RNG, HFLEN_2048);
                while (FF_2048_lastbits(PRIV->p, 2) != 3) FF_2048_inc(PRIV->p, 1, HFLEN_2048);
                while (!FF_2048_prime(PRIV->p, RNG, HFLEN_2048))
                    FF_2048_inc(PRIV->p, 4, HFLEN_2048);

                FF_2048_copy(p1, PRIV->p, HFLEN_2048);
                FF_2048_dec(p1, 1, HFLEN_2048);

                if (FF_2048_cfactor(p1, e, HFLEN_2048)) continue;
                break;
            }

            for (;;)
            {
                FF_2048_random(PRIV->q, RNG, HFLEN_2048);
                while (FF_2048_lastbits(PRIV->q, 2) != 3) FF_2048_inc(PRIV->q, 1, HFLEN_2048);
                while (!FF_2048_prime(PRIV->q, RNG, HFLEN_2048))
                    FF_2048_inc(PRIV->q, 4, HFLEN_2048);

                FF_2048_copy(q1, PRIV->q, HFLEN_2048);
                FF_2048_dec(q1, 1, HFLEN_2048);
                if (FF_2048_cfactor(q1, e, HFLEN_2048)) continue;

                break;
            }
            FF_2048_mul(PUB->n, PRIV->p, PRIV->q, HFLEN_2048);
            if (FF_2048_topbit(PUB->n,FFLEN_2048)==1) break;
        }
    }
    else
    {
        FF_2048_fromOctet(PRIV->p, P, HFLEN_2048);
        FF_2048_fromOctet(PRIV->q, Q, HFLEN_2048);

        FF_2048_copy(p1, PRIV->p, HFLEN_2048);
        FF_2048_dec(p1, 1, HFLEN_2048);

        FF_2048_copy(q1, PRIV->q, HFLEN_2048);
        FF_2048_dec(q1, 1, HFLEN_2048);
        FF_2048_mul(PUB->n, PRIV->p, PRIV->q, HFLEN_2048);
    }

    PUB->e = e;

// Only works for 3 mod 4 primes (as always generated above)

    FF_2048_copy(t, p1, HFLEN_2048);
    FF_2048_shr(t, HFLEN_2048);
    FF_2048_init(PRIV->dp, e, HFLEN_2048);
    FF_2048_invmodp(PRIV->dp, PRIV->dp, t, HFLEN_2048);
    if (FF_2048_parity(PRIV->dp) == 0) FF_2048_add(PRIV->dp, PRIV->dp, t, HFLEN_2048);
    FF_2048_norm(PRIV->dp, HFLEN_2048);

    FF_2048_copy(t, q1, HFLEN_2048);
    FF_2048_shr(t, HFLEN_2048);
    FF_2048_init(PRIV->dq, e, HFLEN_2048);
    FF_2048_invmodp(PRIV->dq, PRIV->dq, t, HFLEN_2048);
    if (FF_2048_parity(PRIV->dq) == 0) FF_2048_add(PRIV->dq, PRIV->dq, t, HFLEN_2048);
    FF_2048_norm(PRIV->dq, HFLEN_2048);

    FF_2048_invmodp(PRIV->c, PRIV->p, PRIV->q, HFLEN_2048);

    return;
}

// Input private key from OpenSSL format
// e.g as in openssl rsa -in privkey.pem -noout -text
// Note order swap - For MIRACL c=1/p mod q, for OpenSSL c=1/q mod p
void RSA_2048_PRIVATE_KEY_FROM_OPENSSL(octet *P,octet* Q,octet *DP,octet *DQ,octet *C,rsa_private_key_2048 *PRIV)
{
    FF_2048_fromOctet(PRIV->p,Q,HFLEN_2048);
    FF_2048_fromOctet(PRIV->q,P,HFLEN_2048);   
    FF_2048_fromOctet(PRIV->dp,DQ,HFLEN_2048);
    FF_2048_fromOctet(PRIV->dq,DP,HFLEN_2048);
    FF_2048_fromOctet(PRIV->c,C,HFLEN_2048);
}

void RSA_2048_KEY_PAIR_FROM_OPENSSL(sign32 e,octet *P,octet* Q,octet *DP,octet *DQ,octet *C,rsa_private_key_2048 *PRIV,rsa_public_key_2048 *PUB)
{ 
    RSA_2048_PRIVATE_KEY_FROM_OPENSSL(P,Q,DP,DQ,C,PRIV);
    FF_2048_mul(PUB->n, PRIV->p, PRIV->q, HFLEN_2048);
    PUB->e = e;
}

/* destroy the Private Key structure */
void RSA_2048_PRIVATE_KEY_KILL(rsa_private_key_2048 *PRIV)
{
    FF_2048_zero(PRIV->p, HFLEN_2048);
    FF_2048_zero(PRIV->q, HFLEN_2048);
    FF_2048_zero(PRIV->dp, HFLEN_2048);
    FF_2048_zero(PRIV->dq, HFLEN_2048);
    FF_2048_zero(PRIV->c, HFLEN_2048);
}

void RSA_2048_fromOctet(BIG_512_60 x[], octet *w)
{
    FF_2048_fromOctet(x, w, FFLEN_2048);
}

/* RSA encryption with the public key */
void RSA_2048_ENCRYPT(rsa_public_key_2048 *PUB, octet *F, octet *G)
{
    BIG_512_60 f[FFLEN_2048];
    FF_2048_fromOctet(f, F, FFLEN_2048);

    FF_2048_power(f, f, PUB->e, PUB->n, FFLEN_2048);

    FF_2048_toOctet(G, f, FFLEN_2048);
}

/* RSA decryption with the private key */
void RSA_2048_DECRYPT(rsa_private_key_2048 *PRIV, octet *G, octet *F)
{
    BIG_512_60 g[FFLEN_2048], t[FFLEN_2048], jp[HFLEN_2048], jq[HFLEN_2048];

    FF_2048_fromOctet(g, G, FFLEN_2048);

    FF_2048_dmod(jp, g, PRIV->p, HFLEN_2048);
    FF_2048_dmod(jq, g, PRIV->q, HFLEN_2048);

    FF_2048_skpow(jp, jp, PRIV->dp, PRIV->p, HFLEN_2048);
    FF_2048_skpow(jq, jq, PRIV->dq, PRIV->q, HFLEN_2048);


    FF_2048_zero(g, FFLEN_2048);
    FF_2048_copy(g, jp, HFLEN_2048);
    FF_2048_mod(jp, PRIV->q, HFLEN_2048);
    if (FF_2048_comp(jp, jq, HFLEN_2048) > 0)
        FF_2048_add(jq, jq, PRIV->q, HFLEN_2048);
    FF_2048_sub(jq, jq, jp, HFLEN_2048);
    FF_2048_norm(jq, HFLEN_2048);

    FF_2048_mul(t, PRIV->c, jq, HFLEN_2048);
    FF_2048_dmod(jq, t, PRIV->q, HFLEN_2048);

    FF_2048_mul(t, jq, PRIV->p, HFLEN_2048);
    FF_2048_add(g, t, g, FFLEN_2048);
    FF_2048_norm(g, FFLEN_2048);

    FF_2048_toOctet(F, g, FFLEN_2048);

    return;
}

