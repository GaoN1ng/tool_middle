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

/* CORE basic functions for Large Finite Field support */

#include "ff_2048.h"

/* x=y */
void FF_2048_copy(BIG_512_60 x[], BIG_512_60 y[], int n)
{
    int i;
    for (i = 0; i < n; i++)
        BIG_512_60_copy(x[i], y[i]);
}

/* x=y<<n */
static void FF_2048_dsucopy(BIG_512_60 x[], BIG_512_60 y[], int n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        BIG_512_60_copy(x[n + i], y[i]);
        BIG_512_60_zero(x[i]);
    }
}

/* x=y */
static void FF_2048_dscopy(BIG_512_60 x[], BIG_512_60 y[], int n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        BIG_512_60_copy(x[i], y[i]);
        BIG_512_60_zero(x[n + i]);
    }
}

/* x=y>>n */
static void FF_2048_sducopy(BIG_512_60 x[], BIG_512_60 y[], int n)
{
    int i;
    for (i = 0; i < n; i++)
        BIG_512_60_copy(x[i], y[n + i]);
}

/* set to zero */
void FF_2048_zero(BIG_512_60 x[], int n)
{
    int i;
    for (i = 0; i < n; i++)
        BIG_512_60_zero(x[i]);
}

/* test equals 0 */
int FF_2048_iszilch(BIG_512_60 x[], int n)
{
    int i;
    for (i = 0; i < n; i++)
        if (!BIG_512_60_iszilch(x[i])) return 0;
    return 1;
}

/* shift right by BIGBITS-bit words */
static void FF_2048_shrw(BIG_512_60 a[], int n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        BIG_512_60_copy(a[i], a[i + n]);
        BIG_512_60_zero(a[i + n]);
    }
}

/* shift left by BIGBITS-bit words */
static void FF_2048_shlw(BIG_512_60 a[], int n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        BIG_512_60_copy(a[i + n], a[i]);
        BIG_512_60_zero(a[i]);
    }
}

/* extract last bit */
int FF_2048_parity(BIG_512_60 x[])
{
    return BIG_512_60_parity(x[0]);
}

/* extract last m bits */
int FF_2048_lastbits(BIG_512_60 x[], int m)
{
    return BIG_512_60_lastbits(x[0], m);
}

/* x=1 */
void FF_2048_one(BIG_512_60 x[], int n)
{
    int i;
    BIG_512_60_one(x[0]);
    for (i = 1; i < n; i++)
        BIG_512_60_zero(x[i]);
}

/* x=m, where m is 32-bit int */
void FF_2048_init(BIG_512_60 x[], sign32 m, int n)
{
    int i;
    BIG_512_60_zero(x[0]);
#if CHUNK<64
    x[0][0] = (chunk)(m & BMASK_512_60);
    x[0][1] = (chunk)(m >> BASEBITS_512_60);
#else
    x[0][0] = (chunk)m;
#endif
    for (i = 1; i < n; i++)
        BIG_512_60_zero(x[i]);
}

/* compare x and y - must be normalised */
int FF_2048_comp(BIG_512_60 x[], BIG_512_60 y[], int n)
{
    int i, j;
    for (i = n - 1; i >= 0; i--)
    {
        j = BIG_512_60_comp(x[i], y[i]);
        if (j != 0) return j;
    }
    return 0;
}

/* recursive add */
static void FF_2048_radd(BIG_512_60 z[], int zp, BIG_512_60 x[], int xp, BIG_512_60 y[], int yp, int n)
{
    int i;
    for (i = 0; i < n; i++)
        BIG_512_60_add(z[zp + i], x[xp + i], y[yp + i]);
}

/* recursive inc */
static void FF_2048_rinc(BIG_512_60 z[], int zp, BIG_512_60 y[], int yp, int n)
{
    int i;
    for (i = 0; i < n; i++)
        BIG_512_60_add(z[zp + i], z[zp + i], y[yp + i]);
}

/* recursive dec */
static void FF_2048_rdec(BIG_512_60 z[], int zp, BIG_512_60 y[], int yp, int n)
{
    int i;
    for (i = 0; i < n; i++)
        BIG_512_60_sub(z[zp + i], z[zp + i], y[yp + i]);
}

/* simple add */
void FF_2048_add(BIG_512_60 z[], BIG_512_60 x[], BIG_512_60 y[], int n)
{
    int i;
    for (i = 0; i < n; i++)
        BIG_512_60_add(z[i], x[i], y[i]);
}

/* simple sub */
void FF_2048_sub(BIG_512_60 z[], BIG_512_60 x[], BIG_512_60 y[], int n)
{
    int i;
    for (i = 0; i < n; i++)
        BIG_512_60_sub(z[i], x[i], y[i]);
}

/* increment/decrement by a small integer */
void FF_2048_inc(BIG_512_60 x[], int m, int n)
{
    BIG_512_60_inc(x[0], m);
    FF_2048_norm(x, n);
}

void FF_2048_dec(BIG_512_60 x[], int m, int n)
{
    BIG_512_60_dec(x[0], m);
    FF_2048_norm(x, n);
}

/* normalise - but hold any overflow in top part unless n<0 */
static void FF_2048_rnorm(BIG_512_60 z[], int zp, int n)
{
    int i, trunc = 0;
    chunk carry;
    if (n < 0)
    {
        /* -v n signals to do truncation */
        n = -n;
        trunc = 1;
    }
    for (i = 0; i < n - 1; i++)
    {
        carry = BIG_512_60_norm(z[zp + i]);

        z[zp + i][NLEN_512_60 - 1] ^= carry << P_TBITS_2048; /* remove it */
        z[zp + i + 1][0] += carry;
    }
    carry = BIG_512_60_norm(z[zp + n - 1]);
    if (trunc) z[zp + n - 1][NLEN_512_60 - 1] ^= carry << P_TBITS_2048;
}

void FF_2048_norm(BIG_512_60 z[], int n)
{
    FF_2048_rnorm(z, 0, n);
}

/* shift left by one bit */
void FF_2048_shl(BIG_512_60 x[], int n)
{
    int i;
    int carry, delay_carry = 0;
    for (i = 0; i < n - 1; i++)
    {
        carry = BIG_512_60_fshl(x[i], 1);
        x[i][0] |= delay_carry;
        x[i][NLEN_512_60 - 1] ^= (chunk)carry << P_TBITS_2048;
        delay_carry = carry;
    }
    BIG_512_60_fshl(x[n - 1], 1);
    x[n - 1][0] |= delay_carry;
}

/* shift right by one bit */
void FF_2048_shr(BIG_512_60 x[], int n)
{
    int i;
    int carry;
    for (i = n - 1; i > 0; i--)
    {
        carry = BIG_512_60_fshr(x[i], 1);
        x[i - 1][NLEN_512_60 - 1] |= (chunk)carry << P_TBITS_2048;
    }
    BIG_512_60_fshr(x[0], 1);
}

void FF_2048_output(BIG_512_60 x[], int n)
{
    int i;
    FF_2048_norm(x, n);
    for (i = n - 1; i >= 0; i--)
    {
        BIG_512_60_output(x[i]);
        printf(" ");
    }
}

void FF_2048_rawoutput(BIG_512_60 x[], int n)
{
    int i;
    for (i = n - 1; i >= 0; i--)
    {
        BIG_512_60_rawoutput(x[i]);
        printf(" ");
    }
}

/* Convert FFs to/from octet strings */
void FF_2048_toOctet(octet *w, BIG_512_60 x[], int n)
{
    int i;
    w->len = n * MODBYTES_512_60;
    for (i = 0; i < n; i++)
    {
        BIG_512_60_toBytes(&(w->val[(n - i - 1)*MODBYTES_512_60]), x[i]);
    }
}

void FF_2048_fromOctet(BIG_512_60 x[], octet *w, int n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        BIG_512_60_fromBytes(x[i], &(w->val[(n - i - 1)*MODBYTES_512_60]));
    }
}

/* in-place swapping using xor - side channel resistant */
static void FF_2048_cswap(BIG_512_60 a[], BIG_512_60 b[], int d, int n)
{
    int i;
    for (i = 0; i < n; i++)
        BIG_512_60_cswap(a[i], b[i], d);
    return;
}

/* z=x*y, t is workspace */
static void FF_2048_karmul(BIG_512_60 z[], int zp, BIG_512_60 x[], int xp, BIG_512_60 y[], int yp, BIG_512_60 t[], int tp, int n)
{
    int nd2;
    if (n == 1)
    {
        BIG_512_60_norm(x[xp]);
        BIG_512_60_norm(y[yp]);
        BIG_512_60_mul(t[tp], x[xp], y[yp]);
        BIG_512_60_split(z[zp + 1], z[zp], t[tp], BIGBITS_512_60);
        return;
    }

    nd2 = n / 2;
    FF_2048_radd(z, zp, x, xp, x, xp + nd2, nd2);
    FF_2048_rnorm(z, zp, nd2); /* needs this if recursion level too deep */

    FF_2048_radd(z, zp + nd2, y, yp, y, yp + nd2, nd2);
    FF_2048_rnorm(z, zp + nd2, nd2);
    FF_2048_karmul(t, tp, z, zp, z, zp + nd2, t, tp + n, nd2);
    FF_2048_karmul(z, zp, x, xp, y, yp, t, tp + n, nd2);
    FF_2048_karmul(z, zp + n, x, xp + nd2, y, yp + nd2, t, tp + n, nd2);
    FF_2048_rdec(t, tp, z, zp, n);
    FF_2048_rdec(t, tp, z, zp + n, n);
    FF_2048_rinc(z, zp + nd2, t, tp, n);
    FF_2048_rnorm(z, zp, 2 * n);
}

static void FF_2048_karsqr(BIG_512_60 z[], int zp, BIG_512_60 x[], int xp, BIG_512_60 t[], int tp, int n)
{
    int nd2;
    if (n == 1)
    {
        BIG_512_60_norm(x[xp]);
        BIG_512_60_sqr(t[tp], x[xp]);
        BIG_512_60_split(z[zp + 1], z[zp], t[tp], BIGBITS_512_60);
        return;
    }
    nd2 = n / 2;
    FF_2048_karsqr(z, zp, x, xp, t, tp + n, nd2);
    FF_2048_karsqr(z, zp + n, x, xp + nd2, t, tp + n, nd2);
    FF_2048_karmul(t, tp, x, xp, x, xp + nd2, t, tp + n, nd2);
    FF_2048_rinc(z, zp + nd2, t, tp, n);
    FF_2048_rinc(z, zp + nd2, t, tp, n);

    FF_2048_rnorm(z, zp + nd2, n); /* was FF_rnorm(z,zp,2*n)  */
}

static void FF_2048_karmul_lower(BIG_512_60 z[], int zp, BIG_512_60 x[], int xp, BIG_512_60 y[], int yp, BIG_512_60 t[], int tp, int n)
{
    /* Calculates Least Significant bottom half of x*y */
    int nd2;
    if (n == 1)
    {
        /* only calculate bottom half of product */
        BIG_512_60_norm(x[xp]);
        BIG_512_60_norm(y[yp]);
        BIG_512_60_smul(z[zp], x[xp], y[yp]);
        return;
    }
    nd2 = n / 2;
    FF_2048_karmul(z, zp, x, xp, y, yp, t, tp + n, nd2);
    FF_2048_karmul_lower(t, tp, x, xp + nd2, y, yp, t, tp + n, nd2);
    FF_2048_rinc(z, zp + nd2, t, tp, nd2);
    FF_2048_karmul_lower(t, tp, x, xp, y, yp + nd2, t, tp + n, nd2);
    FF_2048_rinc(z, zp + nd2, t, tp, nd2);
    FF_2048_rnorm(z, zp + nd2, -nd2); /* truncate it */
}

static void FF_2048_karmul_upper(BIG_512_60 z[], BIG_512_60 x[], BIG_512_60 y[], BIG_512_60 t[], int n)
{
    /* Calculates Most Significant upper half of x*y, given lower part */
    int nd2;

    nd2 = n / 2;
    FF_2048_radd(z, n, x, 0, x, nd2, nd2);
    FF_2048_radd(z, n + nd2, y, 0, y, nd2, nd2);
    FF_2048_rnorm(z, n, nd2);
    FF_2048_rnorm(z, n + nd2, nd2);

    FF_2048_karmul(t, 0, z, n + nd2, z, n, t, n, nd2); /* t = (a0+a1)(b0+b1) */
    FF_2048_karmul(z, n, x, nd2, y, nd2, t, n, nd2); /* z[n]= a1*b1 */
    /* z[0-nd2]=l(a0b0) z[nd2-n]= h(a0b0)+l(t)-l(a0b0)-l(a1b1) */
    FF_2048_rdec(t, 0, z, n, n);          /* t=t-a1b1  */
    FF_2048_rinc(z, nd2, z, 0, nd2); /* z[nd2-n]+=l(a0b0) = h(a0b0)+l(t)-l(a1b1)  */
    FF_2048_rdec(z, nd2, t, 0, nd2); /* z[nd2-n]=h(a0b0)+l(t)-l(a1b1)-l(t-a1b1)=h(a0b0) */
    FF_2048_rnorm(z, 0, -n);                 /* a0b0 now in z - truncate it */
    FF_2048_rdec(t, 0, z, 0, n);     /* (a0+a1)(b0+b1) - a0b0 */
    FF_2048_rinc(z, nd2, t, 0, n);

    FF_2048_rnorm(z, nd2, n);
}

/* z=x*y */
void FF_2048_mul(BIG_512_60 z[], BIG_512_60 x[], BIG_512_60 y[], int n)
{
#ifndef USE_VLAS
    BIG_512_60 t[2 * FFLEN_2048];
#else
    BIG_512_60 t[2 * n];
#endif
    FF_2048_karmul(z, 0, x, 0, y, 0, t, 0, n);
}

/* return low part of product */
static void FF_2048_lmul(BIG_512_60 z[], BIG_512_60 x[], BIG_512_60 y[], int n)
{
#ifndef USE_VLAS
    BIG_512_60 t[2 * FFLEN_2048];
#else
    BIG_512_60 t[2 * n];
#endif
    FF_2048_karmul_lower(z, 0, x, 0, y, 0, t, 0, n);
}

/* Set b=b mod c */
void FF_2048_mod(BIG_512_60 b[], BIG_512_60 c[], int n)
{
    int k = 0;

    FF_2048_norm(b, n);
    if (FF_2048_comp(b, c, n) < 0)
        return;
    do
    {
        FF_2048_shl(c, n);
        k++;
    }
    while (FF_2048_comp(b, c, n) >= 0);

    while (k > 0)
    {
        FF_2048_shr(c, n);
        if (FF_2048_comp(b, c, n) >= 0)
        {
            FF_2048_sub(b, b, c, n);
            FF_2048_norm(b, n);
        }
        k--;
    }
}

/* z=x^2 */
void FF_2048_sqr(BIG_512_60 z[], BIG_512_60 x[], int n)
{
#ifndef USE_VLAS
    BIG_512_60 t[2 * FFLEN_2048];
#else
    BIG_512_60 t[2 * n];
#endif
    FF_2048_karsqr(z, 0, x, 0, t, 0, n);
}

/* r=t mod modulus, N is modulus, ND is Montgomery Constant */
static void FF_2048_reduce(BIG_512_60 r[], BIG_512_60 T[], BIG_512_60 N[], BIG_512_60 ND[], int n)
{
    /* fast karatsuba Montgomery reduction */
#ifndef USE_VLAS
    BIG_512_60 t[2 * FFLEN_2048];
    BIG_512_60 m[FFLEN_2048];
#else
    BIG_512_60 t[2 * n];
    BIG_512_60 m[n];
#endif
    FF_2048_sducopy(r, T, n); /* keep top half of T */
    FF_2048_karmul_lower(m, 0, T, 0, ND, 0, t, 0, n); /* m=T.(1/N) mod R */

    FF_2048_karmul_upper(T, N, m, t, n); /* T=mN */
    FF_2048_sducopy(m, T, n);

    FF_2048_add(r, r, N, n);
    FF_2048_sub(r, r, m, n);
    FF_2048_norm(r, n);
}


/* Set r=a mod b */
/* a is of length - 2*n */
/* r,b is of length - n */
void FF_2048_dmod(BIG_512_60 r[], BIG_512_60 a[], BIG_512_60 b[], int n)
{
    int k;
#ifndef USE_VLAS
    BIG_512_60 m[2 * FFLEN_2048];
    BIG_512_60 x[2 * FFLEN_2048];
#else
    BIG_512_60 m[2 * n];
    BIG_512_60 x[2 * n];
#endif
    FF_2048_copy(x, a, 2 * n);
    FF_2048_norm(x, 2 * n);
    FF_2048_dsucopy(m, b, n);
    k = BIGBITS_512_60 * n;

    while (FF_2048_comp(x, m, 2 * n) >= 0)
    {
        FF_2048_sub(x, x, m, 2 * n);
        FF_2048_norm(x, 2 * n);
    }

    while (k > 0)
    {
        FF_2048_shr(m, 2 * n);

        if (FF_2048_comp(x, m, 2 * n) >= 0)
        {
            FF_2048_sub(x, x, m, 2 * n);
            FF_2048_norm(x, 2 * n);
        }

        k--;
    }
    FF_2048_copy(r, x, n);
    FF_2048_mod(r, b, n);
}

/* Set r=1/a mod p. Binary method - a<p on entry */

void FF_2048_invmodp(BIG_512_60 r[], BIG_512_60 a[], BIG_512_60 p[], int n)
{
#ifndef USE_VLAS
    BIG_512_60 u[FFLEN_2048], v[FFLEN_2048], x1[FFLEN_2048], x2[FFLEN_2048], t[FFLEN_2048], one[FFLEN_2048];
#else
    BIG_512_60 u[n], v[n], x1[n], x2[n], t[n], one[n];
#endif
    FF_2048_copy(u, a, n);
    FF_2048_copy(v, p, n);
    FF_2048_one(one, n);
    FF_2048_copy(x1, one, n);
    FF_2048_zero(x2, n);

// reduce n in here as well!
    while (FF_2048_comp(u, one, n) != 0 && FF_2048_comp(v, one, n) != 0)
    {
        while (FF_2048_parity(u) == 0)
        {
            FF_2048_shr(u, n);
            if (FF_2048_parity(x1) != 0)
            {
                FF_2048_add(x1, p, x1, n);
                FF_2048_norm(x1, n);
            }
            FF_2048_shr(x1, n);
        }
        while (FF_2048_parity(v) == 0)
        {
            FF_2048_shr(v, n);
            if (FF_2048_parity(x2) != 0)
            {
                FF_2048_add(x2, p, x2, n);
                FF_2048_norm(x2, n);
            }
            FF_2048_shr(x2, n);
        }
        if (FF_2048_comp(u, v, n) >= 0)
        {

            FF_2048_sub(u, u, v, n);
            FF_2048_norm(u, n);
            if (FF_2048_comp(x1, x2, n) >= 0) FF_2048_sub(x1, x1, x2, n);
            else
            {
                FF_2048_sub(t, p, x2, n);
                FF_2048_add(x1, x1, t, n);
            }
            FF_2048_norm(x1, n);
        }
        else
        {
            FF_2048_sub(v, v, u, n);
            FF_2048_norm(v, n);
            if (FF_2048_comp(x2, x1, n) >= 0) FF_2048_sub(x2, x2, x1, n);
            else
            {
                FF_2048_sub(t, p, x1, n);
                FF_2048_add(x2, x2, t, n);
            }
            FF_2048_norm(x2, n);
        }
    }
    if (FF_2048_comp(u, one, n) == 0)
        FF_2048_copy(r, x1, n);
    else
        FF_2048_copy(r, x2, n);
}

/* nesidue mod m */
static void FF_2048_nres(BIG_512_60 a[], BIG_512_60 m[], int n)
{
#ifndef USE_VLAS
    BIG_512_60 d[2 * FFLEN_2048];
#else
    BIG_512_60 d[2 * n];
#endif
    if (n == 1)
    {
        BIG_512_60_dscopy(d[0], a[0]);
        BIG_512_60_dshl(d[0], NLEN_512_60 * BASEBITS_512_60);
        BIG_512_60_dmod(a[0], d[0], m[0]);
    }
    else
    {
        FF_2048_dsucopy(d, a, n);
        FF_2048_dmod(a, d, m, n);
    }
}

static void FF_2048_redc(BIG_512_60 a[], BIG_512_60 m[], BIG_512_60 ND[], int n)
{
#ifndef USE_VLAS
    BIG_512_60 d[2 * FFLEN_2048];
#else
    BIG_512_60 d[2 * n];
#endif
    if (n == 1)
    {
        BIG_512_60_dzero(d[0]);
        BIG_512_60_dscopy(d[0], a[0]);
        BIG_512_60_monty(a[0], m[0], ((chunk)1 << BASEBITS_512_60) - ND[0][0], d[0]);
    }
    else
    {
        FF_2048_mod(a, m, n);
        FF_2048_dscopy(d, a, n);
        FF_2048_reduce(a, d, m, ND, n);
        FF_2048_mod(a, m, n);
    }
}

/* U=1/a mod 2^m - Arazi & Qi */
static void FF_2048_invmod2m(BIG_512_60 U[], BIG_512_60 a[], int n)
{
    int i;
#ifndef USE_VLAS
    BIG_512_60 t1[2*FFLEN_2048], b[FFLEN_2048], c[FFLEN_2048];
#else
    BIG_512_60 t1[2 * n], b[n], c[n];
#endif

    FF_2048_zero(U, n);
    FF_2048_zero(b, n);
    FF_2048_zero(c, n);
    FF_2048_zero(t1, 2 * n);

    BIG_512_60_copy(U[0], a[0]);
    BIG_512_60_invmod2m(U[0]);
    for (i = 1; i < n; i <<= 1)
    {
        FF_2048_copy(b, a, i);
        FF_2048_mul(t1, U, b, i);
        FF_2048_shrw(t1, i); // top half to bottom half, top half=0

        FF_2048_copy(c, a, 2 * i);
        FF_2048_shrw(c, i); // top half of c
        FF_2048_lmul(b, U, c, i); // should set top half of b=0
        FF_2048_add(t1, t1, b, i);
        FF_2048_norm(t1, 2 * i);
        FF_2048_lmul(b, t1, U, i);
        FF_2048_copy(t1, b, i);
        FF_2048_one(b, i);
        FF_2048_shlw(b, i);
        FF_2048_sub(t1, b, t1, 2 * i);
        FF_2048_norm(t1, 2 * i);
        FF_2048_shlw(t1, i);
        FF_2048_add(U, U, t1, 2 * i);
    }

    FF_2048_norm(U, n);
}

int FF_2048_topbit(BIG_512_60 x[],int n)
{
    FF_2048_norm(x, n);
    if (BIG_512_60_nbits(x[n - 1]) < MODBYTES_512_60 * 8) return 0;
    return 1;
}

void FF_2048_random(BIG_512_60 x[], csprng *rng, int n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        BIG_512_60_random(x[i], rng);
    }
    /* make sure top bit is 1 */
    while (BIG_512_60_nbits(x[n - 1]) < MODBYTES_512_60 * 8) BIG_512_60_random(x[n - 1], rng);
}

/* generate random x mod p */
void FF_2048_randomnum(BIG_512_60 x[], BIG_512_60 p[], csprng *rng, int n)
{
    int i;
#ifndef USE_VLAS
    BIG_512_60 d[2 * FFLEN_2048];
#else
    BIG_512_60 d[2 * n];
#endif
    for (i = 0; i < 2 * n; i++)
    {
        BIG_512_60_random(d[i], rng);
    }
    FF_2048_dmod(x, d, p, n);
}

static void FF_2048_modmul(BIG_512_60 z[], BIG_512_60 x[], BIG_512_60 y[], BIG_512_60 p[], BIG_512_60 ND[], int n)
{
#ifndef USE_VLAS
    BIG_512_60 d[2 * FFLEN_2048];
#else
    BIG_512_60 d[2 * n];
#endif
    chunk ex = P_EXCESS_2048(x[n - 1]);
    chunk ey = P_EXCESS_2048(y[n - 1]);
#ifdef dchunk
    if ((dchunk)(ex + 1) * (ey + 1) > (dchunk)P_FEXCESS_2048)
#else
    if ((ex + 1) > P_FEXCESS_2048 / (ey + 1))
#endif
    {
#ifdef DEBUG_REDUCE
        printf("Product too large - reducing it %d %d\n", ex, ey);
#endif
        FF_2048_mod(x, p, n);
    }

    if (n == 1)
    {
        BIG_512_60_mul(d[0], x[0], y[0]);
        BIG_512_60_monty(z[0], p[0], ((chunk)1 << BASEBITS_512_60) - ND[0][0], d[0]);
    }
    else
    {
        FF_2048_mul(d, x, y, n);
        FF_2048_reduce(z, d, p, ND, n);
    }
}

static void FF_2048_modsqr(BIG_512_60 z[], BIG_512_60 x[], BIG_512_60 p[], BIG_512_60 ND[], int n)
{
#ifndef USE_VLAS
    BIG_512_60 d[2 * FFLEN_2048];
#else
    BIG_512_60 d[2 * n];
#endif
    chunk ex = P_EXCESS_2048(x[n - 1]);
#ifdef dchunk
    if ((dchunk)(ex + 1) * (ex + 1) > (dchunk)P_FEXCESS_2048)
#else
    if ((ex + 1) > P_FEXCESS_2048 / (ex + 1))
#endif
    {
#ifdef DEBUG_REDUCE
        printf("Product too large - reducing it %d\n", ex);
#endif
        FF_2048_mod(x, p, n);
    }
    if (n == 1)
    {
        BIG_512_60_sqr(d[0], x[0]);
        BIG_512_60_monty(z[0], p[0], ((chunk)1 << BASEBITS_512_60) - ND[0][0], d[0]);
    }
    else
    {
        FF_2048_sqr(d, x, n);
        FF_2048_reduce(z, d, p, ND, n);
    }
}

/* r=x^e mod p using side-channel resistant Montgomery Ladder, for large e */
void FF_2048_skpow(BIG_512_60 r[], BIG_512_60 x[], BIG_512_60 e[], BIG_512_60 p[], int n)
{
    int i, b;
#ifndef USE_VLAS
    BIG_512_60 R0[FFLEN_2048], R1[FFLEN_2048], ND[FFLEN_2048];
#else
    BIG_512_60 R0[n], R1[n], ND[n];
#endif
    FF_2048_invmod2m(ND, p, n);

    FF_2048_one(R0, n);
    FF_2048_copy(R1, x, n);
    FF_2048_nres(R0, p, n);
    FF_2048_nres(R1, p, n);

    for (i = 8 * MODBYTES_512_60 * n - 1; i >= 0; i--)
    {
        b = BIG_512_60_bit(e[i / BIGBITS_512_60], i % BIGBITS_512_60);
        FF_2048_modmul(r, R0, R1, p, ND, n);

        FF_2048_cswap(R0, R1, b, n);
        FF_2048_modsqr(R0, R0, p, ND, n);

        FF_2048_copy(R1, r, n);
        FF_2048_cswap(R0, R1, b, n);
    }
    FF_2048_copy(r, R0, n);
    FF_2048_redc(r, p, ND, n);
}

/* r=x^e mod p using side-channel resistant Montgomery Ladder, for short e */
void FF_2048_skspow(BIG_512_60 r[], BIG_512_60 x[], BIG_512_60 e, BIG_512_60 p[], int n)
{
    int i, b;
#ifndef USE_VLAS
    BIG_512_60 R0[FFLEN_2048], R1[FFLEN_2048], ND[FFLEN_2048];
#else
    BIG_512_60 R0[n], R1[n], ND[n];
#endif
    FF_2048_invmod2m(ND, p, n);
    FF_2048_one(R0, n);
    FF_2048_copy(R1, x, n);
    FF_2048_nres(R0, p, n);
    FF_2048_nres(R1, p, n);
    for (i = 8 * MODBYTES_512_60 - 1; i >= 0; i--)
    {
        b = BIG_512_60_bit(e, i);
        FF_2048_modmul(r, R0, R1, p, ND, n);
        FF_2048_cswap(R0, R1, b, n);
        FF_2048_modsqr(R0, R0, p, ND, n);
        FF_2048_copy(R1, r, n);
        FF_2048_cswap(R0, R1, b, n);
    }
    FF_2048_copy(r, R0, n);
    FF_2048_redc(r, p, ND, n);
}

/* raise to an integer power - right-to-left method */
void FF_2048_power(BIG_512_60 r[], BIG_512_60 x[], int e, BIG_512_60 p[], int n)
{
    int f = 1;
#ifndef USE_VLAS
    BIG_512_60 w[FFLEN_2048], ND[FFLEN_2048];
#else
    BIG_512_60 w[n], ND[n];
#endif
    FF_2048_invmod2m(ND, p, n);

    FF_2048_copy(w, x, n);
    FF_2048_nres(w, p, n);

    if (e == 2)
    {
        FF_2048_modsqr(r, w, p, ND, n);
    }
    else for (;;)
        {
            if (e % 2 == 1)
            {
                if (f) FF_2048_copy(r, w, n);
                else FF_2048_modmul(r, r, w, p, ND, n);
                f = 0;
            }
            e >>= 1;
            if (e == 0) break;
            FF_2048_modsqr(w, w, p, ND, n);
        }

    FF_2048_redc(r, p, ND, n);
}

/* r=x^e mod p, faster but not side channel resistant */
void FF_2048_pow(BIG_512_60 r[], BIG_512_60 x[], BIG_512_60 e[], BIG_512_60 p[], int n)
{
    int i, b;
#ifndef USE_VLAS
    BIG_512_60 w[FFLEN_2048], ND[FFLEN_2048];
#else
    BIG_512_60 w[n], ND[n];
#endif
    FF_2048_invmod2m(ND, p, n);

    FF_2048_copy(w, x, n);
    FF_2048_one(r, n);
    FF_2048_nres(r, p, n);
    FF_2048_nres(w, p, n);

    for (i = 8 * MODBYTES_512_60 * n - 1; i >= 0; i--)
    {
        FF_2048_modsqr(r, r, p, ND, n);
        b = BIG_512_60_bit(e[i / BIGBITS_512_60], i % BIGBITS_512_60);
        if (b == 1) FF_2048_modmul(r, r, w, p, ND, n);
    }
    FF_2048_redc(r, p, ND, n);
}

/* double exponentiation r=x^e.y^f mod p */
void FF_2048_pow2(BIG_512_60 r[], BIG_512_60 x[], BIG_512_60 e, BIG_512_60 y[], BIG_512_60 f, BIG_512_60 p[], int n)
{
    int i, eb, fb;
#ifndef USE_VLAS
    BIG_512_60 xn[FFLEN_2048], yn[FFLEN_2048], xy[FFLEN_2048], ND[FFLEN_2048];
#else
    BIG_512_60 xn[n], yn[n], xy[n], ND[n];
#endif

    FF_2048_invmod2m(ND, p, n);

    FF_2048_copy(xn, x, n);
    FF_2048_copy(yn, y, n);
    FF_2048_nres(xn, p, n);
    FF_2048_nres(yn, p, n);
    FF_2048_modmul(xy, xn, yn, p, ND, n);
    FF_2048_one(r, n);
    FF_2048_nres(r, p, n);

    for (i = 8 * MODBYTES_512_60 - 1; i >= 0; i--)
    {
        eb = BIG_512_60_bit(e, i);
        fb = BIG_512_60_bit(f, i);
        FF_2048_modsqr(r, r, p, ND, n);
        if (eb == 1)
        {
            if (fb == 1) FF_2048_modmul(r, r, xy, p, ND, n);
            else FF_2048_modmul(r, r, xn, p, ND, n);
        }
        else
        {
            if (fb == 1) FF_2048_modmul(r, r, yn, p, ND, n);
        }
    }
    FF_2048_redc(r, p, ND, n);
}

static sign32 igcd(sign32 x, sign32 y)
{
    /* integer GCD, returns GCD of x and y */
    sign32 r;
    if (y == 0) return x;
    while ((r = x % y) != 0)
        x = y, y = r;
    return y;
}

/* quick and dirty check for common factor with s */
int FF_2048_cfactor(BIG_512_60 w[], sign32 s, int n)
{
    int r;
    sign32 g;
#ifndef USE_VLAS
    BIG_512_60 x[FFLEN_2048], y[FFLEN_2048];
#else
    BIG_512_60 x[n], y[n];
#endif
    FF_2048_init(y, s, n);
    FF_2048_copy(x, w, n);
    FF_2048_norm(x, n);

    do
    {
        FF_2048_sub(x, x, y, n);
        FF_2048_norm(x, n);
        while (!FF_2048_iszilch(x, n) && FF_2048_parity(x) == 0) FF_2048_shr(x, n);
    }
    while (FF_2048_comp(x, y, n) > 0);
#if CHUNK<32
    g = x[0][0] + ((sign32)(x[0][1]) << BASEBITS_512_60);
#else
    g = (sign32)x[0][0];
#endif
    r = igcd(s, g);
    if (r > 1) return 1;
    return 0;
}

/* Miller-Rabin test for primality. Slow. */
int FF_2048_prime(BIG_512_60 p[], csprng *rng, int n)
{
    int i, j, loop, s = 0;
#ifndef USE_VLAS
    BIG_512_60 d[FFLEN_2048], x[FFLEN_2048], unity[FFLEN_2048], nm1[FFLEN_2048];
#else
    BIG_512_60 d[n], x[n], unity[n], nm1[n];
#endif
    sign32 sf = 4849845; /* 3*5*.. *19 */

    FF_2048_norm(p, n);

    if (FF_2048_cfactor(p, sf, n)) return 0;

    FF_2048_one(unity, n);
    FF_2048_sub(nm1, p, unity, n);
    FF_2048_norm(nm1, n);
    FF_2048_copy(d, nm1, n);
    while (FF_2048_parity(d) == 0)
    {
        FF_2048_shr(d, n);
        s++;
    }
    if (s == 0) return 0;

    for (i = 0; i < 10; i++)
    {
        FF_2048_randomnum(x, p, rng, n);
        FF_2048_pow(x, x, d, p, n);
        if (FF_2048_comp(x, unity, n) == 0 || FF_2048_comp(x, nm1, n) == 0) continue;
        loop = 0;
        for (j = 1; j < s; j++)
        {
            FF_2048_power(x, x, 2, p, n);
            if (FF_2048_comp(x, unity, n) == 0) return 0;
            if (FF_2048_comp(x, nm1, n) == 0 )
            {
                loop = 1;
                break;
            }
        }
        if (loop) continue;
        return 0;
    }

    return 1;
}
