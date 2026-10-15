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

/* CORE basic functions for BIG type */
/* SU=m, SU is Stack Usage */

#include "big_512_60.h"

/* test a=0? */
int BIG_512_60_iszilch(BIG_512_60 a)
{
    int i;
    chunk d=0;
    for (i = 0; i < NLEN_512_60; i++)
        d|=a[i];
    return (1 & ((d-1)>>BASEBITS_512_60));
}

/* test a=1? */
int BIG_512_60_isunity(BIG_512_60 a)
{
    int i;
    chunk d=0;
    for (i = 1; i < NLEN_512_60; i++)
        d|=a[i];
    return (1 & ((d-1)>>BASEBITS_512_60) & (((a[0]^1)-1)>>BASEBITS_512_60));
}

/* test a=0? */
int BIG_512_60_diszilch(DBIG_512_60 a)
{
    int i;
    chunk d=0;
    for (i = 0; i < DNLEN_512_60; i++)
        d|=a[i];
    return (1 & ((d-1)>>BASEBITS_512_60));
}

/* SU= 56 */
/* output a */
void BIG_512_60_output(BIG_512_60 a)
{
    BIG_512_60 b;
    int i, len;
    len = BIG_512_60_nbits(a);
    if (len % 4 == 0) len /= 4;
    else
    {
        len /= 4;
        len++;
    }
    if (len < MODBYTES_512_60 * 2) len = MODBYTES_512_60 * 2;

    for (i = len - 1; i >= 0; i--)
    {
        BIG_512_60_copy(b, a);
        BIG_512_60_shr(b, i * 4);
        printf("%01x", (unsigned int) b[0] & 15);
    }
}

/* SU= 16 */
void BIG_512_60_rawoutput(BIG_512_60 a)
{
    int i;
    printf("(");
    for (i = 0; i < NLEN_512_60 - 1; i++)
#if CHUNK==64
        printf("%"PRIxMAX",", (uintmax_t) a[i]);
    printf("%"PRIxMAX")", (uintmax_t) a[NLEN_512_60 - 1]);
#else
        printf("%x,", (unsigned int) a[i]);
    printf("%x)", (unsigned int) a[NLEN_512_60 - 1]);
#endif
}

// See Loiseau et al. 2021
chunk BIG_512_60_cmove(volatile BIG_512_60 f, BIG_512_60 g, int d)
{
    int i;
    chunk c0,c1,s,t,w,aux;
    static chunk R=0;
    R+=CONDMS;
    w=R;
    c0=(~d)&(w+1);
    c1=d+w;
#ifdef DEBUG_NORM
    for (i = 0; i < NLEN_512_60 + 2; i++)
#else
    for (i = 0; i < NLEN_512_60; i++)
#endif
    {
        s=g[i]; t=f[i];
        f[i] =aux=c0*t+c1*s;
        f[i] =aux-w*(t+s);  
    }
    return 0;
}

chunk BIG_512_60_cswap(volatile BIG_512_60 f, volatile BIG_512_60 g, int d)
{
    int i;
    chunk c0,c1,s,t,w,v,aux;
    static chunk R=0;
    R+=CONDMS;
    w=R;
    c0=(~d)&(w+1);
    c1=d+w;
#ifdef DEBUG_NORM
    for (i = 0; i < NLEN_512_60 + 2; i++)
#else
    for (i = 0; i < NLEN_512_60; i++)
#endif
    {
        s=g[i]; t=f[i];
        v=w*(t+s);
        f[i] =aux=c0*t+c1*s;
        f[i] =aux-v;  
        g[i] =aux=c0*s+c1*t;
        g[i] =aux-v; 
    }
    return 0;
}

chunk BIG_512_60_dcmove(volatile DBIG_512_60 f, DBIG_512_60 g, int d)
{
    int i;
    chunk c0,c1,s,t,w,aux;
    static chunk R=0;
    R+=CONDMS;
    w=R;
    c0=(~d)&(w+1);
    c1=d+w;
#ifdef DEBUG_NORM
    for (i = 0; i < DNLEN_512_60 + 2; i++)
#else
    for (i = 0; i < DNLEN_512_60; i++)
#endif
    {
        s=g[i]; t=f[i];
        f[i] =aux=c0*t+c1*s;
        f[i] =aux-w*(t+s);
    }
    return 0;
}


/* Swap a and b if d=1 
chunk BIG_512_60_cswap(BIG_512_60 a, BIG_512_60 b, int d)
{
    int i;
    chunk e,r,ra,w,t, c = (chunk) - d;
    w=0; 
    r=a[0]^b[1]; 
    ra=r+r; ra>>=1; // I know this doesn't change r, but the compiler doesn't!
#ifdef DEBUG_NORM
    for (i = 0; i < NLEN_512_60 + 2; i++)
#else
    for (i = 0; i < NLEN_512_60; i++)
#endif
    {
        t = c & (a[i] ^ b[i]);
        t^=r; 
        e=a[i]^t; w^=e;  // to force calculation of e
        a[i] = e^ra;
        e=b[i]^t; w^=e;
        b[i] = e^ra;
    }
    return w;
}
*/
/* Move g to f if d=1 
chunk BIG_512_60_cmove(BIG_512_60 f, BIG_512_60 g, int d)
{
    int i;
    chunk e,w,r,ra,t,b = (chunk) - d;
    w=0;
    r=f[0]^g[1];
    ra=r+r; ra>>=1; // I know this doesn't change r, but the compiler doesn't!
#ifdef DEBUG_NORM
    for (i = 0; i < NLEN_512_60 + 2; i++)
#else
    for (i = 0; i < NLEN_512_60; i++)
#endif
    {
        t=(f[i] ^ g[i])&b;
        t^=r;
        e=f[i]^t; w^=e;
        f[i] = e^ra;
    }
    return w;
}
*/
/* Move g to f if d=1 
chunk BIG_512_60_dcmove(DBIG_512_60 f, DBIG_512_60 g, int d)
{
    int i;
    chunk e,w,r,ra,t,b = (chunk) - d;
    w=0;
    r=f[0]+g[1];
    ra=r+r; ra>>=1; // I know this doesn't change r, but the compiler doesn't!
#ifdef DEBUG_NORM
    for (i = 0; i < DNLEN_512_60 + 2; i++)
#else
    for (i = 0; i < DNLEN_512_60; i++)
#endif
    {
        t=(f[i] ^ g[i])&b;
        t^=r;
        e=f[i]^t; w^=e;
        f[i] = e^ra;
    }
    return w;
}
*/
/* convert BIG to/from bytes */
/* SU= 64 */
void BIG_512_60_toBytes(char *b, BIG_512_60 a)
{
    int i;
    BIG_512_60 c;
    BIG_512_60_copy(c, a);
    BIG_512_60_norm(c);
    for (i = MODBYTES_512_60 - 1; i >= 0; i--)
    {
        b[i] = c[0] & 0xff;
        BIG_512_60_fshr(c, 8);
    }
}

/* SU= 16 */
void BIG_512_60_fromBytes(BIG_512_60 a, char *b)
{
    int i;
    BIG_512_60_zero(a);
    for (i = 0; i < MODBYTES_512_60; i++)
    {
        BIG_512_60_fshl(a, 8);
        a[0] += (int)(unsigned char)b[i];
    }
#ifdef DEBUG_NORM
    a[MPV_512_60] = 1;
    a[MNV_512_60] = 0;
#endif
}

void BIG_512_60_fromBytesLen(BIG_512_60 a, char *b, int s)
{
    int i, len = s;
    BIG_512_60_zero(a);

    if (len > MODBYTES_512_60) len = MODBYTES_512_60;
    for (i = 0; i < len; i++)
    {
        BIG_512_60_fshl(a, 8);
        a[0] += (int)(unsigned char)b[i];
    }
#ifdef DEBUG_NORM
    a[MPV_512_60] = 1;
    a[MNV_512_60] = 0;
#endif
}



/* SU= 88 */
void BIG_512_60_doutput(DBIG_512_60 a)
{
    DBIG_512_60 b;
    int i, len;
    BIG_512_60_dnorm(a);
    len = BIG_512_60_dnbits(a);
    if (len % 4 == 0) len /= 4;
    else
    {
        len /= 4;
        len++;
    }

    for (i = len - 1; i >= 0; i--)
    {
        BIG_512_60_dcopy(b, a);
        BIG_512_60_dshr(b, i * 4);
        printf("%01x", (unsigned int) b[0] & 15);
    }
}


void BIG_512_60_drawoutput(DBIG_512_60 a)
{
    int i;
    printf("(");
    for (i = 0; i < DNLEN_512_60 - 1; i++)
#if CHUNK==64
        printf("%"PRIxMAX",", (uintmax_t) a[i]);
    printf("%"PRIxMAX")", (uintmax_t) a[DNLEN_512_60 - 1]);
#else
        printf("%x,", (unsigned int) a[i]);
    printf("%x)", (unsigned int) a[DNLEN_512_60 - 1]);
#endif
}

/* Copy b=a */
void BIG_512_60_copy(BIG_512_60 b, BIG_512_60 a)
{
    int i;
    for (i = 0; i < NLEN_512_60; i++)
        b[i] = a[i];
#ifdef DEBUG_NORM
    b[MPV_512_60] = a[MPV_512_60];
    b[MNV_512_60] = a[MNV_512_60];
#endif
}

/* Copy from ROM b=a */
void BIG_512_60_rcopy(BIG_512_60 b, const BIG_512_60 a)
{
    int i;
    for (i = 0; i < NLEN_512_60; i++)
        b[i] = a[i];
#ifdef DEBUG_NORM
    b[MPV_512_60] = 1;
    b[MNV_512_60] = 0;
#endif
}

/* double length DBIG copy b=a */
void BIG_512_60_dcopy(DBIG_512_60 b, DBIG_512_60 a)
{
    int i;
    for (i = 0; i < DNLEN_512_60; i++)
        b[i] = a[i];
#ifdef DEBUG_NORM
    b[DMPV_512_60] = a[DMPV_512_60];
    b[DMNV_512_60] = a[DMNV_512_60];
#endif
}

/* Copy BIG to bottom half of DBIG */
void BIG_512_60_dscopy(DBIG_512_60 b, BIG_512_60 a)
{
    int i;
    for (i = 0; i < NLEN_512_60 - 1; i++)
        b[i] = a[i];

    b[NLEN_512_60 - 1] = a[NLEN_512_60 - 1] & BMASK_512_60; /* top word normalized */
    b[NLEN_512_60] = a[NLEN_512_60 - 1] >> BASEBITS_512_60;

    for (i = NLEN_512_60 + 1; i < DNLEN_512_60; i++) b[i] = 0;
#ifdef DEBUG_NORM
    b[DMPV_512_60] = a[MPV_512_60];
    b[DMNV_512_60] = a[MNV_512_60];
#endif
}

/* Copy BIG to top half of DBIG */
void BIG_512_60_dsucopy(DBIG_512_60 b, BIG_512_60 a)
{
    int i;
    for (i = 0; i < NLEN_512_60; i++)
        b[i] = 0;
    for (i = NLEN_512_60; i < DNLEN_512_60; i++)
        b[i] = a[i - NLEN_512_60];
#ifdef DEBUG_NORM
    b[DMPV_512_60] = a[MPV_512_60];
    b[DMNV_512_60] = a[MNV_512_60];
#endif
}

/* Copy bottom half of DBIG to BIG */
void BIG_512_60_sdcopy(BIG_512_60 b, DBIG_512_60 a)
{
    int i;
    for (i = 0; i < NLEN_512_60; i++)
        b[i] = a[i];
#ifdef DEBUG_NORM
    b[MPV_512_60] = a[DMPV_512_60];
    b[MNV_512_60] = a[DMNV_512_60];
#endif
}

/* Copy top half of DBIG to BIG */
void BIG_512_60_sducopy(BIG_512_60 b, DBIG_512_60 a)
{
    int i;
    for (i = 0; i < NLEN_512_60; i++)
        b[i] = a[i + NLEN_512_60];
#ifdef DEBUG_NORM
    b[MPV_512_60] = a[DMPV_512_60];
    b[MNV_512_60] = a[DMNV_512_60];

#endif
}

/* Set a=0 */
void BIG_512_60_zero(BIG_512_60 a)
{
    int i;
    for (i = 0; i < NLEN_512_60; i++)
        a[i] = 0;
#ifdef DEBUG_NORM
    a[MPV_512_60] = a[MNV_512_60] = 0;
#endif
}

void BIG_512_60_dzero(DBIG_512_60 a)
{
    int i;
    for (i = 0; i < DNLEN_512_60; i++)
        a[i] = 0;
#ifdef DEBUG_NORM
    a[DMPV_512_60] = a[DMNV_512_60] = 0;
#endif
}

/* set a=1 */
void BIG_512_60_one(BIG_512_60 a)
{
    int i;
    a[0] = 1;
    for (i = 1; i < NLEN_512_60; i++)
        a[i] = 0;
#ifdef DEBUG_NORM
    a[MPV_512_60] = 1;
    a[MNV_512_60] = 0;
#endif
}



/* Set c=a+b */
/* SU= 8 */
void BIG_512_60_add(BIG_512_60 c, BIG_512_60 a, BIG_512_60 b)
{
    int i;
    for (i = 0; i < NLEN_512_60; i++)
        c[i] = a[i] + b[i];
#ifdef DEBUG_NORM
    c[MPV_512_60] = a[MPV_512_60] + b[MPV_512_60];
    c[MNV_512_60] = a[MNV_512_60] + b[MNV_512_60];
    if (c[MPV_512_60] > NEXCESS_512_60)  printf("add problem - positive digit overflow %d\n", (int)c[MPV_512_60]);
    if (c[MNV_512_60] > NEXCESS_512_60)  printf("add problem - negative digit overflow %d\n", (int)c[MNV_512_60]);

#endif
}

/* Set c=a or b */
void BIG_512_60_or(BIG_512_60 c, BIG_512_60 a, BIG_512_60 b)
{
    int i;
    BIG_512_60_norm(a);
    BIG_512_60_norm(b);
    for (i = 0; i < NLEN_512_60; i++)
        c[i] = a[i] | b[i];
#ifdef DEBUG_NORM
    c[MPV_512_60] = 1;
    c[MNV_512_60] = 0;
#endif
}


/* Set c=c+d */
void BIG_512_60_inc(BIG_512_60 c, int d)
{
    BIG_512_60_norm(c);
    c[0] += (chunk)d;
#ifdef DEBUG_NORM
    c[MPV_512_60] += 1;
#endif
}

/* Set c=a-b */
/* SU= 8 */
void BIG_512_60_sub(BIG_512_60 c, BIG_512_60 a, BIG_512_60 b)
{
    int i;
    for (i = 0; i < NLEN_512_60; i++)
        c[i] = a[i] - b[i];
#ifdef DEBUG_NORM
    c[MPV_512_60] = a[MPV_512_60] + b[MNV_512_60];
    c[MNV_512_60] = a[MNV_512_60] + b[MPV_512_60];
    if (c[MPV_512_60] > NEXCESS_512_60)  printf("sub problem - positive digit overflow %d\n", (int)c[MPV_512_60]);
    if (c[MNV_512_60] > NEXCESS_512_60)  printf("sub problem - negative digit overflow %d\n", (int)c[MNV_512_60]);

#endif
}

/* SU= 8 */

void BIG_512_60_dsub(DBIG_512_60 c, DBIG_512_60 a, DBIG_512_60 b)
{
    int i;
    for (i = 0; i < DNLEN_512_60; i++)
        c[i] = a[i] - b[i];
#ifdef DEBUG_NORM
    c[DMPV_512_60] = a[DMPV_512_60] + b[DMNV_512_60];
    c[DMNV_512_60] = a[DMNV_512_60] + b[DMPV_512_60];
    if (c[DMPV_512_60] > NEXCESS_512_60)  printf("double sub problem - positive digit overflow %d\n", (int)c[DMPV_512_60]);
    if (c[DMNV_512_60] > NEXCESS_512_60)  printf("double sub problem - negative digit overflow %d\n", (int)c[DMNV_512_60]);
#endif
}

void BIG_512_60_dadd(DBIG_512_60 c, DBIG_512_60 a, DBIG_512_60 b)
{
    int i;
    for (i = 0; i < DNLEN_512_60; i++)
        c[i] = a[i] + b[i];
#ifdef DEBUG_NORM
    c[DMPV_512_60] = a[DMPV_512_60] + b[DMNV_512_60];
    c[DMNV_512_60] = a[DMNV_512_60] + b[DMPV_512_60];
    if (c[DMPV_512_60] > NEXCESS_512_60)  printf("double add problem - positive digit overflow %d\n", (int)c[DMPV_512_60]);
    if (c[DMNV_512_60] > NEXCESS_512_60)  printf("double add problem - negative digit overflow %d\n", (int)c[DMNV_512_60]);
#endif
}

/* Set c=c-1 */
void BIG_512_60_dec(BIG_512_60 c, int d)
{
    BIG_512_60_norm(c);
    c[0] -= (chunk)d;
#ifdef DEBUG_NORM
    c[MNV_512_60] += 1;
#endif
}

/* multiplication r=a*c by c<=NEXCESS_512_60 */
void BIG_512_60_imul(BIG_512_60 r, BIG_512_60 a, int c)
{
    int i;
    for (i = 0; i < NLEN_512_60; i++) r[i] = a[i] * c;
#ifdef DEBUG_NORM
    r[MPV_512_60] = a[MPV_512_60] * c;
    r[MNV_512_60] = a[MNV_512_60] * c;
    if (r[MPV_512_60] > NEXCESS_512_60)  printf("int mul problem - positive digit overflow %d\n", (int)r[MPV_512_60]);
    if (r[MNV_512_60] > NEXCESS_512_60)  printf("int mul problem - negative digit overflow %d\n", (int)r[MNV_512_60]);

#endif
}

/* multiplication r=a*c by larger integer - c<=FEXCESS */
/* SU= 24 */
chunk BIG_512_60_pmul(BIG_512_60 r, BIG_512_60 a, int c)
{
    int i;
    chunk ak, carry = 0;
    for (i = 0; i < NLEN_512_60; i++)
    {
        ak = a[i];
        r[i] = 0;
        carry = muladd_512_60(ak, (chunk)c, carry, &r[i]);
    }
#ifdef DEBUG_NORM
    r[MPV_512_60] = 1;
    r[MNV_512_60] = 0;
#endif
    return carry;
}

/* r/=3 */
/* SU= 16 */
int BIG_512_60_div3(BIG_512_60 r)
{
    int i;
    chunk ak, base, carry = 0;
    BIG_512_60_norm(r);
    base = ((chunk)1 << BASEBITS_512_60);
    for (i = NLEN_512_60 - 1; i >= 0; i--)
    {
        ak = (carry * base + r[i]);
        r[i] = ak / 3;
        carry = ak % 3;
    }
    return (int)carry;
}

/* multiplication c=a*b by even larger integer b>FEXCESS, resulting in DBIG */
/* SU= 24 */
void BIG_512_60_pxmul(DBIG_512_60 c, BIG_512_60 a, int b)
{
    int j;
    chunk carry;
    BIG_512_60_dzero(c);
    carry = 0;
    for (j = 0; j < NLEN_512_60; j++)
        carry = muladd_512_60(a[j], (chunk)b, carry, &c[j]);
    c[NLEN_512_60] = carry;
#ifdef DEBUG_NORM
    c[DMPV_512_60] = 1;
    c[DMNV_512_60] = 0;
#endif
}

/* .. if you know the result will fit in a BIG, c must be distinct from a and b */
/* SU= 40 */
void BIG_512_60_smul(BIG_512_60 c, BIG_512_60 a, BIG_512_60 b)
{
    int i, j;
    chunk carry;

    BIG_512_60_zero(c);
    for (i = 0; i < NLEN_512_60; i++)
    {
        carry = 0;
        for (j = 0; j < NLEN_512_60; j++)
        {
            if (i + j < NLEN_512_60)
                carry = muladd_512_60(a[i], b[j], carry, &c[i + j]);
        }
    }
#ifdef DEBUG_NORM
    c[MPV_512_60] = 1;
    c[MNV_512_60] = 0;
#endif

}

/* Set c=a*b */
/* SU= 72 */
//void BIG_512_60_mul(chunk c[restrict DNLEN_512_60],chunk a[restrict NLEN_512_60],chunk b[restrict NLEN_512_60])
void BIG_512_60_mul(DBIG_512_60 c, BIG_512_60 a, BIG_512_60 b)
{
    int i;
#ifdef dchunk
    dchunk t, co;
    dchunk s;
    dchunk d[NLEN_512_60];
    int k;
#endif

#ifdef DEBUG_NORM
    if ((a[MPV_512_60] != 1 && a[MPV_512_60] != 0) || a[MNV_512_60] != 0) printf("First input to mul not normed\n");
    if ((b[MPV_512_60] != 1 && b[MPV_512_60] != 0) || b[MNV_512_60] != 0) printf("Second input to mul not normed\n");
#endif

    /* Faster to Combafy it.. Let the compiler unroll the loops! */

#ifdef COMBA

    /* faster psuedo-Karatsuba method */
#ifdef UNWOUND

#ifdef USE_KARATSUBA

    	d[0]=(dchunk)a[0]*b[0];
	d[1]=(dchunk)a[1]*b[1];
	d[2]=(dchunk)a[2]*b[2];
	d[3]=(dchunk)a[3]*b[3];
	d[4]=(dchunk)a[4]*b[4];
	d[5]=(dchunk)a[5]*b[5];
	d[6]=(dchunk)a[6]*b[6];
	d[7]=(dchunk)a[7]*b[7];
	d[8]=(dchunk)a[8]*b[8];

	s=d[0];
	t = s; c[0]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60;
	s+=d[1]; t=co+s +(dchunk)(a[1]-a[0])*(b[0]-b[1]); c[1]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s+=d[2]; t=co+s +(dchunk)(a[2]-a[0])*(b[0]-b[2]); c[2]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s+=d[3]; t=co+s +(dchunk)(a[3]-a[0])*(b[0]-b[3])+(dchunk)(a[2]-a[1])*(b[1]-b[2]); c[3]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s+=d[4]; t=co+s +(dchunk)(a[4]-a[0])*(b[0]-b[4])+(dchunk)(a[3]-a[1])*(b[1]-b[3]); c[4]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s+=d[5]; t=co+s +(dchunk)(a[5]-a[0])*(b[0]-b[5])+(dchunk)(a[4]-a[1])*(b[1]-b[4])+(dchunk)(a[3]-a[2])*(b[2]-b[3]); c[5]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s+=d[6]; t=co+s +(dchunk)(a[6]-a[0])*(b[0]-b[6])+(dchunk)(a[5]-a[1])*(b[1]-b[5])+(dchunk)(a[4]-a[2])*(b[2]-b[4]); c[6]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s+=d[7]; t=co+s +(dchunk)(a[7]-a[0])*(b[0]-b[7])+(dchunk)(a[6]-a[1])*(b[1]-b[6])+(dchunk)(a[5]-a[2])*(b[2]-b[5])+(dchunk)(a[4]-a[3])*(b[3]-b[4]); c[7]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s+=d[8]; t=co+s +(dchunk)(a[8]-a[0])*(b[0]-b[8])+(dchunk)(a[7]-a[1])*(b[1]-b[7])+(dchunk)(a[6]-a[2])*(b[2]-b[6])+(dchunk)(a[5]-a[3])*(b[3]-b[5]); c[8]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 

	s-=d[0]; t=co+s +(dchunk)(a[8]-a[1])*(b[1]-b[8])+(dchunk)(a[7]-a[2])*(b[2]-b[7])+(dchunk)(a[6]-a[3])*(b[3]-b[6])+(dchunk)(a[5]-a[4])*(b[4]-b[5]); c[9]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s-=d[1]; t=co+s +(dchunk)(a[8]-a[2])*(b[2]-b[8])+(dchunk)(a[7]-a[3])*(b[3]-b[7])+(dchunk)(a[6]-a[4])*(b[4]-b[6]); c[10]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s-=d[2]; t=co+s +(dchunk)(a[8]-a[3])*(b[3]-b[8])+(dchunk)(a[7]-a[4])*(b[4]-b[7])+(dchunk)(a[6]-a[5])*(b[5]-b[6]); c[11]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s-=d[3]; t=co+s +(dchunk)(a[8]-a[4])*(b[4]-b[8])+(dchunk)(a[7]-a[5])*(b[5]-b[7]); c[12]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s-=d[4]; t=co+s +(dchunk)(a[8]-a[5])*(b[5]-b[8])+(dchunk)(a[7]-a[6])*(b[6]-b[7]); c[13]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s-=d[5]; t=co+s +(dchunk)(a[8]-a[6])*(b[6]-b[8]); c[14]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s-=d[6]; t=co+s +(dchunk)(a[8]-a[7])*(b[7]-b[8]); c[15]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	s-=d[7]; t=co+s ; c[16]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	c[17]=(chunk)co;


#else

    	t=(dchunk)a[0]*b[0]; c[0]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[0]*b[1]+(dchunk)a[1]*b[0]; c[1]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[0]*b[2]+(dchunk)a[1]*b[1]+(dchunk)a[2]*b[0]; c[2]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[0]*b[3]+(dchunk)a[1]*b[2]+(dchunk)a[2]*b[1]+(dchunk)a[3]*b[0]; c[3]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[0]*b[4]+(dchunk)a[1]*b[3]+(dchunk)a[2]*b[2]+(dchunk)a[3]*b[1]+(dchunk)a[4]*b[0]; c[4]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[0]*b[5]+(dchunk)a[1]*b[4]+(dchunk)a[2]*b[3]+(dchunk)a[3]*b[2]+(dchunk)a[4]*b[1]+(dchunk)a[5]*b[0]; c[5]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[0]*b[6]+(dchunk)a[1]*b[5]+(dchunk)a[2]*b[4]+(dchunk)a[3]*b[3]+(dchunk)a[4]*b[2]+(dchunk)a[5]*b[1]+(dchunk)a[6]*b[0]; c[6]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[0]*b[7]+(dchunk)a[1]*b[6]+(dchunk)a[2]*b[5]+(dchunk)a[3]*b[4]+(dchunk)a[4]*b[3]+(dchunk)a[5]*b[2]+(dchunk)a[6]*b[1]+(dchunk)a[7]*b[0]; c[7]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[0]*b[8]+(dchunk)a[1]*b[7]+(dchunk)a[2]*b[6]+(dchunk)a[3]*b[5]+(dchunk)a[4]*b[4]+(dchunk)a[5]*b[3]+(dchunk)a[6]*b[2]+(dchunk)a[7]*b[1]+(dchunk)a[8]*b[0]; c[8]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[1]*b[8]+(dchunk)a[2]*b[7]+(dchunk)a[3]*b[6]+(dchunk)a[4]*b[5]+(dchunk)a[5]*b[4]+(dchunk)a[6]*b[3]+(dchunk)a[7]*b[2]+(dchunk)a[8]*b[1]; c[9]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[2]*b[8]+(dchunk)a[3]*b[7]+(dchunk)a[4]*b[6]+(dchunk)a[5]*b[5]+(dchunk)a[6]*b[4]+(dchunk)a[7]*b[3]+(dchunk)a[8]*b[2]; c[10]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[3]*b[8]+(dchunk)a[4]*b[7]+(dchunk)a[5]*b[6]+(dchunk)a[6]*b[5]+(dchunk)a[7]*b[4]+(dchunk)a[8]*b[3]; c[11]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[4]*b[8]+(dchunk)a[5]*b[7]+(dchunk)a[6]*b[6]+(dchunk)a[7]*b[5]+(dchunk)a[8]*b[4]; c[12]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[5]*b[8]+(dchunk)a[6]*b[7]+(dchunk)a[7]*b[6]+(dchunk)a[8]*b[5]; c[13]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[6]*b[8]+(dchunk)a[7]*b[7]+(dchunk)a[8]*b[6]; c[14]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[7]*b[8]+(dchunk)a[8]*b[7]; c[15]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	t=t+(dchunk)a[8]*b[8]; c[16]=(chunk)t & BMASK_512_60; t=t>>BASEBITS_512_60;
	c[17]=(chunk)t;


#endif


#else

#ifndef USE_KARATSUBA

    t=(dchunk)a[0]*b[0];
    c[0]=(chunk)t & BMASK_512_60;
    t = t >> BASEBITS_512_60;
    for (i=1;i<NLEN_512_60;i++)
    {
        k=0; 
        while (k<=i) {t+=(dchunk)a[k]*b[i-k]; k++;}
        c[i]=(chunk)t & BMASK_512_60;
        t = t >> BASEBITS_512_60;
    }

    for (i=NLEN_512_60;i<2*NLEN_512_60-1;i++)
    {
        k=i-(NLEN_512_60-1);
        while (k<=NLEN_512_60-1) {t+=(dchunk)a[k]*b[i-k]; k++;}
        c[i]=(chunk)t & BMASK_512_60;
        t = t >> BASEBITS_512_60;
    }

    c[2 * NLEN_512_60 - 1] = (chunk)t;
#else

    for (i = 0; i < NLEN_512_60; i++)
        d[i] = (dchunk)a[i] * b[i];

    s = d[0];
    t = s;
    c[0] = (chunk)t & BMASK_512_60;
    co = t >> BASEBITS_512_60;

    for (k = 1; k < NLEN_512_60; k++)
    {
        s += d[k];
        t = co + s;
        
        /*for (i = k; i >= 1 + k / 2; i--) This causes a huge slow down! gcc/g++ optimizer problem (I think) */
        for (i=1+k/2;i<=k;i++) t += (dchunk)(a[i] - a[k - i]) * (b[k - i] - b[i]);
        c[k] = (chunk)t & BMASK_512_60;
        co = t >> BASEBITS_512_60;
    }
    for (k = NLEN_512_60; k < 2 * NLEN_512_60 - 1; k++)
    {
        s -= d[k - NLEN_512_60];
        t = co + s;
        for (i=1+k/2;i<NLEN_512_60;i++) t += (dchunk)(a[i] - a[k - i]) * (b[k - i] - b[i]);
        c[k] = (chunk)t & BMASK_512_60;
        co = t >> BASEBITS_512_60;
    }
    c[2 * NLEN_512_60 - 1] = (chunk)co;
#endif
#endif

#else
    int j;
    chunk carry;
    BIG_512_60_dzero(c);
    for (i = 0; i < NLEN_512_60; i++)
    {
        carry = 0;
        for (j = 0; j < NLEN_512_60; j++)
            carry = muladd_512_60(a[i], b[j], carry, &c[i + j]);

        c[NLEN_512_60 + i] = carry;
    }

#endif

#ifdef DEBUG_NORM
    c[DMPV_512_60] = 1;
    c[DMNV_512_60] = 0;
#endif
}

/* Set c=a*a */
/* SU= 80 */

//void BIG_512_60_sqr(chunk c[restrict DNLEN_512_60],chunk a[restrict NLEN_512_60])
void BIG_512_60_sqr(DBIG_512_60 c, BIG_512_60 a)
{
    int i, j;
#ifdef dchunk
    dchunk t, co;
#endif

#ifdef DEBUG_NORM
    if ((a[MPV_512_60] != 1 && a[MPV_512_60] != 0) || a[MNV_512_60] != 0) printf("Input to sqr not normed\n");
#endif
    /* Note 2*a[i] in loop below and extra addition */

#ifdef COMBA

#ifdef UNWOUND

    
	t=(dchunk)a[0]*a[0]; c[0]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60;
	t= +(dchunk)a[1]*a[0]; t+=t; t+=co; c[1]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[2]*a[0]; t+=t; t+=co; t+=(dchunk)a[1]*a[1]; c[2]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[3]*a[0]+(dchunk)a[2]*a[1]; t+=t; t+=co; c[3]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[4]*a[0]+(dchunk)a[3]*a[1]; t+=t; t+=co; t+=(dchunk)a[2]*a[2]; c[4]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[5]*a[0]+(dchunk)a[4]*a[1]+(dchunk)a[3]*a[2]; t+=t; t+=co; c[5]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[6]*a[0]+(dchunk)a[5]*a[1]+(dchunk)a[4]*a[2]; t+=t; t+=co; t+=(dchunk)a[3]*a[3]; c[6]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[7]*a[0]+(dchunk)a[6]*a[1]+(dchunk)a[5]*a[2]+(dchunk)a[4]*a[3]; t+=t; t+=co; c[7]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[8]*a[0]+(dchunk)a[7]*a[1]+(dchunk)a[6]*a[2]+(dchunk)a[5]*a[3]; t+=t; t+=co; t+=(dchunk)a[4]*a[4]; c[8]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 

	t= +(dchunk)a[8]*a[1]+(dchunk)a[7]*a[2]+(dchunk)a[6]*a[3]+(dchunk)a[5]*a[4]; t+=t; t+=co; c[9]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[8]*a[2]+(dchunk)a[7]*a[3]+(dchunk)a[6]*a[4]; t+=t; t+=co; t+=(dchunk)a[5]*a[5]; c[10]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[8]*a[3]+(dchunk)a[7]*a[4]+(dchunk)a[6]*a[5]; t+=t; t+=co; c[11]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[8]*a[4]+(dchunk)a[7]*a[5]; t+=t; t+=co; t+=(dchunk)a[6]*a[6]; c[12]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[8]*a[5]+(dchunk)a[7]*a[6]; t+=t; t+=co; c[13]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[8]*a[6]; t+=t; t+=co; t+=(dchunk)a[7]*a[7]; c[14]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t= +(dchunk)a[8]*a[7]; t+=t; t+=co; c[15]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
	t=co; t+=(dchunk)a[8]*a[8]; c[16]=(chunk)t&BMASK_512_60; co=t>>BASEBITS_512_60; 
 	c[17]=(chunk)co;


#else


    t = (dchunk)a[0] * a[0];
    c[0] = (chunk)t & BMASK_512_60;
    co = t >> BASEBITS_512_60;

    for (j = 1; j < NLEN_512_60 - 1; )
    {
        t = (dchunk)a[j] * a[0];
        for (i = 1; i < (j + 1) / 2; i++)
        {
            t += (dchunk)a[j - i] * a[i];
        }
        t += t;
        t += co;
        c[j] = (chunk)t & BMASK_512_60;
        co = t >> BASEBITS_512_60;
        j++;
        t = (dchunk)a[j] * a[0];
        for (i = 1; i < (j + 1) / 2; i++)
        {
            t += (dchunk)a[j - i] * a[i];
        }
        t += t;
        t += co;
        t += (dchunk)a[j / 2] * a[j / 2];
        c[j] = (chunk)t & BMASK_512_60;
        co = t >> BASEBITS_512_60;
        j++;
    }

    for (j = NLEN_512_60 - 1 + NLEN_512_60 % 2; j < DNLEN_512_60 - 3; )
    {
        t = (dchunk)a[NLEN_512_60 - 1] * a[j - NLEN_512_60 + 1];
        for (i = j - NLEN_512_60 + 2; i < (j + 1) / 2; i++)
        {
            t += (dchunk)a[j - i] * a[i];
        }
        t += t;
        t += co;
        c[j] = (chunk)t & BMASK_512_60;
        co = t >> BASEBITS_512_60;
        j++;
        t = (dchunk)a[NLEN_512_60 - 1] * a[j - NLEN_512_60 + 1];
        for (i = j - NLEN_512_60 + 2; i < (j + 1) / 2; i++)
        {
            t += (dchunk)a[j - i] * a[i];
        }
        t += t;
        t += co;
        t += (dchunk)a[j / 2] * a[j / 2];
        c[j] = (chunk)t & BMASK_512_60;
        co = t >> BASEBITS_512_60;
        j++;
    }

    t = (dchunk)a[NLEN_512_60 - 2] * a[NLEN_512_60 - 1];
    t += t;
    t += co;
    c[DNLEN_512_60 - 3] = (chunk)t & BMASK_512_60;
    co = t >> BASEBITS_512_60;

    t = (dchunk)a[NLEN_512_60 - 1] * a[NLEN_512_60 - 1] + co;
    c[DNLEN_512_60 - 2] = (chunk)t & BMASK_512_60;
    co = t >> BASEBITS_512_60;
    c[DNLEN_512_60 - 1] = (chunk)co;


#endif

#else
    chunk carry;
    BIG_512_60_dzero(c);
    for (i = 0; i < NLEN_512_60; i++)
    {
        carry = 0;
        for (j = i + 1; j < NLEN_512_60; j++)
            carry = muladd_512_60(a[i], a[j], carry, &c[i + j]);
        c[NLEN_512_60 + i] = carry;
    }

    for (i = 0; i < DNLEN_512_60; i++) c[i] *= 2;

    for (i = 0; i < NLEN_512_60; i++)
        c[2 * i + 1] += muladd_512_60(a[i], a[i], 0, &c[2 * i]);

    BIG_512_60_dnorm(c);
#endif


#ifdef DEBUG_NORM
    c[DMPV_512_60] = 1;
    c[DMNV_512_60] = 0;
#endif

}

/* Montgomery reduction */
//void BIG_512_60_monty(chunk a[restrict NLEN_512_60], chunk md[restrict NLEN_512_60], chunk MC, chunk d[restrict DNLEN_512_60])
void BIG_512_60_monty(BIG_512_60 a, BIG_512_60 md, chunk MC, DBIG_512_60 d)
{
    int i, k;

#ifdef dchunk
    dchunk t, c, s;
    dchunk dd[NLEN_512_60];
    chunk v[NLEN_512_60];
#endif

#ifdef DEBUG_NORM
    if ((d[DMPV_512_60] != 1 && d[DMPV_512_60] != 0) || d[DMNV_512_60] != 0) printf("Input to redc not normed\n");
#endif

#ifdef COMBA

#ifdef UNWOUND

#ifdef USE_KARATSUBA

    	t=d[0]; v[0]=((chunk)t*MC)&BMASK_512_60; t+=(dchunk)v[0]*md[0];  s=0; c=(t>>BASEBITS_512_60);

	t=d[1]+c+s+(dchunk)v[0]*md[1]; v[1]=((chunk)t*MC)&BMASK_512_60; t+=(dchunk)v[1]*md[0];  dd[1]=(dchunk)v[1]*md[1]; s+=dd[1]; c=(t>>BASEBITS_512_60); 
	t=d[2]+c+s+(dchunk)v[0]*md[2]; v[2]=((chunk)t*MC)&BMASK_512_60; t+=(dchunk)v[2]*md[0];  dd[2]=(dchunk)v[2]*md[2]; s+=dd[2]; c=(t>>BASEBITS_512_60); 
	t=d[3]+c+s+(dchunk)v[0]*md[3]+(dchunk)(v[1]-v[2])*(md[2]-md[1]); v[3]=((chunk)t*MC)&BMASK_512_60; t+=(dchunk)v[3]*md[0];  dd[3]=(dchunk)v[3]*md[3]; s+=dd[3]; c=(t>>BASEBITS_512_60); 
	t=d[4]+c+s+(dchunk)v[0]*md[4]+(dchunk)(v[1]-v[3])*(md[3]-md[1]); v[4]=((chunk)t*MC)&BMASK_512_60; t+=(dchunk)v[4]*md[0];  dd[4]=(dchunk)v[4]*md[4]; s+=dd[4]; c=(t>>BASEBITS_512_60); 
	t=d[5]+c+s+(dchunk)v[0]*md[5]+(dchunk)(v[1]-v[4])*(md[4]-md[1])+(dchunk)(v[2]-v[3])*(md[3]-md[2]); v[5]=((chunk)t*MC)&BMASK_512_60; t+=(dchunk)v[5]*md[0];  dd[5]=(dchunk)v[5]*md[5]; s+=dd[5]; c=(t>>BASEBITS_512_60); 
	t=d[6]+c+s+(dchunk)v[0]*md[6]+(dchunk)(v[1]-v[5])*(md[5]-md[1])+(dchunk)(v[2]-v[4])*(md[4]-md[2]); v[6]=((chunk)t*MC)&BMASK_512_60; t+=(dchunk)v[6]*md[0];  dd[6]=(dchunk)v[6]*md[6]; s+=dd[6]; c=(t>>BASEBITS_512_60); 
	t=d[7]+c+s+(dchunk)v[0]*md[7]+(dchunk)(v[1]-v[6])*(md[6]-md[1])+(dchunk)(v[2]-v[5])*(md[5]-md[2])+(dchunk)(v[3]-v[4])*(md[4]-md[3]); v[7]=((chunk)t*MC)&BMASK_512_60; t+=(dchunk)v[7]*md[0];  dd[7]=(dchunk)v[7]*md[7]; s+=dd[7]; c=(t>>BASEBITS_512_60); 
	t=d[8]+c+s+(dchunk)v[0]*md[8]+(dchunk)(v[1]-v[7])*(md[7]-md[1])+(dchunk)(v[2]-v[6])*(md[6]-md[2])+(dchunk)(v[3]-v[5])*(md[5]-md[3]); v[8]=((chunk)t*MC)&BMASK_512_60; t+=(dchunk)v[8]*md[0];  dd[8]=(dchunk)v[8]*md[8]; s+=dd[8]; c=(t>>BASEBITS_512_60); 

	t=d[9]+c+s+(dchunk)(v[1]-v[8])*(md[8]-md[1])+(dchunk)(v[2]-v[7])*(md[7]-md[2])+(dchunk)(v[3]-v[6])*(md[6]-md[3])+(dchunk)(v[4]-v[5])*(md[5]-md[4]); a[0]=(chunk)t&BMASK_512_60;  s-=dd[1]; c=(t>>BASEBITS_512_60); 
	t=d[10]+c+s+(dchunk)(v[2]-v[8])*(md[8]-md[2])+(dchunk)(v[3]-v[7])*(md[7]-md[3])+(dchunk)(v[4]-v[6])*(md[6]-md[4]); a[1]=(chunk)t&BMASK_512_60;  s-=dd[2]; c=(t>>BASEBITS_512_60); 
	t=d[11]+c+s+(dchunk)(v[3]-v[8])*(md[8]-md[3])+(dchunk)(v[4]-v[7])*(md[7]-md[4])+(dchunk)(v[5]-v[6])*(md[6]-md[5]); a[2]=(chunk)t&BMASK_512_60;  s-=dd[3]; c=(t>>BASEBITS_512_60); 
	t=d[12]+c+s+(dchunk)(v[4]-v[8])*(md[8]-md[4])+(dchunk)(v[5]-v[7])*(md[7]-md[5]); a[3]=(chunk)t&BMASK_512_60;  s-=dd[4]; c=(t>>BASEBITS_512_60); 
	t=d[13]+c+s+(dchunk)(v[5]-v[8])*(md[8]-md[5])+(dchunk)(v[6]-v[7])*(md[7]-md[6]); a[4]=(chunk)t&BMASK_512_60;  s-=dd[5]; c=(t>>BASEBITS_512_60); 
	t=d[14]+c+s+(dchunk)(v[6]-v[8])*(md[8]-md[6]); a[5]=(chunk)t&BMASK_512_60;  s-=dd[6]; c=(t>>BASEBITS_512_60); 
	t=d[15]+c+s+(dchunk)(v[7]-v[8])*(md[8]-md[7]); a[6]=(chunk)t&BMASK_512_60;  s-=dd[7]; c=(t>>BASEBITS_512_60); 
	t=d[16]+c+s; a[7]=(chunk)t&BMASK_512_60;  s-=dd[8]; c=(t>>BASEBITS_512_60); 
	a[8]=d[17]+((chunk)c&BMASK_512_60);


#else

    	t = d[0];
	v[0] = ((chunk)t * MC)&BMASK_512_60;
	t += (dchunk)v[0] * md[0];
	t = (t >> BASEBITS_512_60) + d[1];
	t += (dchunk)v[0] * md[1] ; v[1] = ((chunk)t * MC)&BMASK_512_60; t += (dchunk)v[1] * md[0]; t = (t >> BASEBITS_512_60) + d[2];
	t += (dchunk)v[0] * md[2] + (dchunk)v[1]*md[1]; v[2] = ((chunk)t * MC)&BMASK_512_60; t += (dchunk)v[2] * md[0]; t = (t >> BASEBITS_512_60) + d[3];
	t += (dchunk)v[0] * md[3] + (dchunk)v[1]*md[2]+ (dchunk)v[2]*md[1]; v[3] = ((chunk)t * MC)&BMASK_512_60; t += (dchunk)v[3] * md[0]; t = (t >> BASEBITS_512_60) + d[4];
	t += (dchunk)v[0] * md[4] + (dchunk)v[1]*md[3]+ (dchunk)v[2]*md[2]+ (dchunk)v[3]*md[1]; v[4] = ((chunk)t * MC)&BMASK_512_60; t += (dchunk)v[4] * md[0]; t = (t >> BASEBITS_512_60) + d[5];
	t += (dchunk)v[0] * md[5] + (dchunk)v[1]*md[4]+ (dchunk)v[2]*md[3]+ (dchunk)v[3]*md[2]+ (dchunk)v[4]*md[1]; v[5] = ((chunk)t * MC)&BMASK_512_60; t += (dchunk)v[5] * md[0]; t = (t >> BASEBITS_512_60) + d[6];
	t += (dchunk)v[0] * md[6] + (dchunk)v[1]*md[5]+ (dchunk)v[2]*md[4]+ (dchunk)v[3]*md[3]+ (dchunk)v[4]*md[2]+ (dchunk)v[5]*md[1]; v[6] = ((chunk)t * MC)&BMASK_512_60; t += (dchunk)v[6] * md[0]; t = (t >> BASEBITS_512_60) + d[7];
	t += (dchunk)v[0] * md[7] + (dchunk)v[1]*md[6]+ (dchunk)v[2]*md[5]+ (dchunk)v[3]*md[4]+ (dchunk)v[4]*md[3]+ (dchunk)v[5]*md[2]+ (dchunk)v[6]*md[1]; v[7] = ((chunk)t * MC)&BMASK_512_60; t += (dchunk)v[7] * md[0]; t = (t >> BASEBITS_512_60) + d[8];
	t += (dchunk)v[0] * md[8] + (dchunk)v[1]*md[7]+ (dchunk)v[2]*md[6]+ (dchunk)v[3]*md[5]+ (dchunk)v[4]*md[4]+ (dchunk)v[5]*md[3]+ (dchunk)v[6]*md[2]+ (dchunk)v[7]*md[1]; v[8] = ((chunk)t * MC)&BMASK_512_60; t += (dchunk)v[8] * md[0]; t = (t >> BASEBITS_512_60) + d[9];
	t=t + (dchunk)v[1]*md[8] + (dchunk)v[2]*md[7] + (dchunk)v[3]*md[6] + (dchunk)v[4]*md[5] + (dchunk)v[5]*md[4] + (dchunk)v[6]*md[3] + (dchunk)v[7]*md[2] + (dchunk)v[8]*md[1] ; a[0] = (chunk)t & BMASK_512_60; t = (t >> BASEBITS_512_60) + d[10];
	t=t + (dchunk)v[2]*md[8] + (dchunk)v[3]*md[7] + (dchunk)v[4]*md[6] + (dchunk)v[5]*md[5] + (dchunk)v[6]*md[4] + (dchunk)v[7]*md[3] + (dchunk)v[8]*md[2] ; a[1] = (chunk)t & BMASK_512_60; t = (t >> BASEBITS_512_60) + d[11];
	t=t + (dchunk)v[3]*md[8] + (dchunk)v[4]*md[7] + (dchunk)v[5]*md[6] + (dchunk)v[6]*md[5] + (dchunk)v[7]*md[4] + (dchunk)v[8]*md[3] ; a[2] = (chunk)t & BMASK_512_60; t = (t >> BASEBITS_512_60) + d[12];
	t=t + (dchunk)v[4]*md[8] + (dchunk)v[5]*md[7] + (dchunk)v[6]*md[6] + (dchunk)v[7]*md[5] + (dchunk)v[8]*md[4] ; a[3] = (chunk)t & BMASK_512_60; t = (t >> BASEBITS_512_60) + d[13];
	t=t + (dchunk)v[5]*md[8] + (dchunk)v[6]*md[7] + (dchunk)v[7]*md[6] + (dchunk)v[8]*md[5] ; a[4] = (chunk)t & BMASK_512_60; t = (t >> BASEBITS_512_60) + d[14];
	t=t + (dchunk)v[6]*md[8] + (dchunk)v[7]*md[7] + (dchunk)v[8]*md[6] ; a[5] = (chunk)t & BMASK_512_60; t = (t >> BASEBITS_512_60) + d[15];
	t=t + (dchunk)v[7]*md[8] + (dchunk)v[8]*md[7] ; a[6] = (chunk)t & BMASK_512_60; t = (t >> BASEBITS_512_60) + d[16];
	t=t + (dchunk)v[8]*md[8] ; a[7] = (chunk)t & BMASK_512_60; t = (t >> BASEBITS_512_60) + d[17];
	a[8] = (chunk)t & BMASK_512_60;


#endif


#else
#ifndef USE_KARATSUBA 
    t = d[0];
    v[0] = ((chunk)t * MC)&BMASK_512_60;
    t += (dchunk)v[0] * md[0];
    t = (t >> BASEBITS_512_60) + d[1];
   
    for (i = 1; i < NLEN_512_60; i++)
    {
        k=1;
        t += (dchunk)v[0] * md[i];
        while (k<i) {t += (dchunk)v[k]*md[i-k]; k++;}
        v[i] = ((chunk)t * MC)&BMASK_512_60;
        t += (dchunk)v[i] * md[0];
        t = (t >> BASEBITS_512_60) + d[i + 1];
    }
    for (i = NLEN_512_60; i < 2 * NLEN_512_60 - 1; i++)
    {
        k=i-(NLEN_512_60-1);
        while (k<=NLEN_512_60-1) {t += (dchunk)v[k]*md[i-k]; k++;}
        a[i - NLEN_512_60] = (chunk)t & BMASK_512_60;
        t = (t >> BASEBITS_512_60) + d[i + 1];
    }
    a[NLEN_512_60 - 1] = (chunk)t & BMASK_512_60;
#else
    t = d[0];
    v[0] = ((chunk)t * MC)&BMASK_512_60;
    t += (dchunk)v[0] * md[0];
    c = (t >> BASEBITS_512_60) + d[1];
    s = 0;

    for (k = 1; k < NLEN_512_60; k++)
    {
        t = c + s + (dchunk)v[0] * md[k];
        for (i=1+k/2;i<k;i++) t += (dchunk)(v[k - i] - v[i]) * (md[i] - md[k - i]);
        v[k] = ((chunk)t * MC)&BMASK_512_60;
        t += (dchunk)v[k] * md[0];
        c = (t >> BASEBITS_512_60) + d[k + 1];
        dd[k] = (dchunk)v[k] * md[k];
        s += dd[k];
    }
    for (k = NLEN_512_60; k < 2 * NLEN_512_60 - 1; k++)
    {
        t = c + s;
        for (i=1+k/2;i<NLEN_512_60;i++) t += (dchunk)(v[k - i] - v[i]) * (md[i] - md[k - i]);
        a[k - NLEN_512_60] = (chunk)t & BMASK_512_60;
        c = (t >> BASEBITS_512_60) + d[k + 1];
        s -= dd[k - NLEN_512_60 + 1];
    }
    a[NLEN_512_60 - 1] = (chunk)c & BMASK_512_60;

#endif
#endif


#else
    int j;
    chunk m, carry;
    for (i = 0; i < NLEN_512_60; i++)
    {
        if (MC == -1) m = (-d[i])&BMASK_512_60;
        else
        {
            if (MC == 1) m = d[i];
            else m = (MC * d[i])&BMASK_512_60;
        }
        carry = 0;
        for (j = 0; j < NLEN_512_60; j++)
            carry = muladd_512_60(m, md[j], carry, &d[i + j]);
        d[NLEN_512_60 + i] += carry;
    }
    BIG_512_60_sducopy(a, d);
    BIG_512_60_norm(a);

#endif

#ifdef DEBUG_NORM
    a[MPV_512_60] = 1;
    a[MNV_512_60] = 0;
#endif
}

/* General shift left of a by n bits */
/* a MUST be normalised */
/* SU= 32 */
void BIG_512_60_shl(BIG_512_60 a, int k)
{
    int i;
    int n = k % BASEBITS_512_60;
    int m = k / BASEBITS_512_60;

    a[NLEN_512_60 - 1] = ((a[NLEN_512_60 - 1 - m] << n));
    if (NLEN_512_60 >= m + 2) a[NLEN_512_60 - 1] |= (a[NLEN_512_60 - m - 2] >> (BASEBITS_512_60 - n));

    for (i = NLEN_512_60 - 2; i > m; i--)
        a[i] = ((a[i - m] << n)&BMASK_512_60) | (a[i - m - 1] >> (BASEBITS_512_60 - n));
    a[m] = (a[0] << n)&BMASK_512_60;
    for (i = 0; i < m; i++) a[i] = 0;

}

/* Fast shift left of a by n bits, where n less than a word, Return excess (but store it as well) */
/* a MUST be normalised */
/* SU= 16 */
int BIG_512_60_fshl(BIG_512_60 a, int n)
{
    int i;

    a[NLEN_512_60 - 1] = ((a[NLEN_512_60 - 1] << n)) | (a[NLEN_512_60 - 2] >> (BASEBITS_512_60 - n)); /* top word not masked */
    for (i = NLEN_512_60 - 2; i > 0; i--)
        a[i] = ((a[i] << n)&BMASK_512_60) | (a[i - 1] >> (BASEBITS_512_60 - n));
    a[0] = (a[0] << n)&BMASK_512_60;

    return (int)(a[NLEN_512_60 - 1] >> ((8 * MODBYTES_512_60) % BASEBITS_512_60)); /* return excess - only used in ff.c */
}

/* double length left shift of a by k bits - k can be > BASEBITS , a MUST be normalised */
/* SU= 32 */
void BIG_512_60_dshl(DBIG_512_60 a, int k)
{
    int i;
    int n = k % BASEBITS_512_60;
    int m = k / BASEBITS_512_60;

    a[DNLEN_512_60 - 1] = ((a[DNLEN_512_60 - 1 - m] << n)) | (a[DNLEN_512_60 - m - 2] >> (BASEBITS_512_60 - n));

    for (i = DNLEN_512_60 - 2; i > m; i--)
        a[i] = ((a[i - m] << n)&BMASK_512_60) | (a[i - m - 1] >> (BASEBITS_512_60 - n));
    a[m] = (a[0] << n)&BMASK_512_60;
    for (i = 0; i < m; i++) a[i] = 0;

}

/* General shift right of a by k bits */
/* a MUST be normalised */
/* SU= 32 */
void BIG_512_60_shr(BIG_512_60 a, int k)
{
    int i;
    int n = k % BASEBITS_512_60;
    int m = k / BASEBITS_512_60;
    for (i = 0; i < NLEN_512_60 - m - 1; i++)
        a[i] = (a[m + i] >> n) | ((a[m + i + 1] << (BASEBITS_512_60 - n))&BMASK_512_60);
    if (NLEN_512_60 > m)  a[NLEN_512_60 - m - 1] = a[NLEN_512_60 - 1] >> n;
    for (i = NLEN_512_60 - m; i < NLEN_512_60; i++) a[i] = 0;

}

/* Fast combined shift, subtract and norm. Return sign of result */
int BIG_512_60_ssn(BIG_512_60 r, BIG_512_60 a, BIG_512_60 m)
{
    int i, n = NLEN_512_60 - 1;
    chunk carry;
    m[0] = (m[0] >> 1) | ((m[1] << (BASEBITS_512_60 - 1))&BMASK_512_60);
    r[0] = a[0] - m[0];
    carry = r[0] >> BASEBITS_512_60;
    r[0] &= BMASK_512_60;

    for (i = 1; i < n; i++)
    {
        m[i] = (m[i] >> 1) | ((m[i + 1] << (BASEBITS_512_60 - 1))&BMASK_512_60);
        r[i] = a[i] - m[i] + carry;
        carry = r[i] >> BASEBITS_512_60;
        r[i] &= BMASK_512_60;
    }

    m[n] >>= 1;
    r[n] = a[n] - m[n] + carry;
#ifdef DEBUG_NORM
    r[MPV_512_60] = 1;
    r[MNV_512_60] = 0;
#endif
    return ((r[n] >> (CHUNK - 1)) & 1);
}

/* Faster shift right of a by k bits. Return shifted out part */
/* a MUST be normalised */
/* SU= 16 */
int BIG_512_60_fshr(BIG_512_60 a, int k)
{
    int i;
    chunk r = a[0] & (((chunk)1 << k) - 1); /* shifted out part */
    for (i = 0; i < NLEN_512_60 - 1; i++)
        a[i] = (a[i] >> k) | ((a[i + 1] << (BASEBITS_512_60 - k))&BMASK_512_60);
    a[NLEN_512_60 - 1] = a[NLEN_512_60 - 1] >> k;
    return (int)r;
}

/* double length right shift of a by k bits - can be > BASEBITS */
/* SU= 32 */
void BIG_512_60_dshr(DBIG_512_60 a, int k)
{
    int i;
    int n = k % BASEBITS_512_60;
    int m = k / BASEBITS_512_60;
    for (i = 0; i < DNLEN_512_60 - m - 1; i++)
        a[i] = (a[m + i] >> n) | ((a[m + i + 1] << (BASEBITS_512_60 - n))&BMASK_512_60);
    a[DNLEN_512_60 - m - 1] = a[DNLEN_512_60 - 1] >> n;
    for (i = DNLEN_512_60 - m; i < DNLEN_512_60; i++ ) a[i] = 0;
}

/* Split DBIG d into two BIGs t|b. Split happens at n bits, where n falls into NLEN word */
/* d MUST be normalised */
/* SU= 24 */
chunk BIG_512_60_split(BIG_512_60 t, BIG_512_60 b, DBIG_512_60 d, int n)
{
    int i;
    chunk nw, carry = 0;
    int m = n % BASEBITS_512_60;

    if (m == 0)
    {
        for (i = 0; i < NLEN_512_60; i++) b[i] = d[i];
        if (t != b)
        {
            for (i = NLEN_512_60; i < 2 * NLEN_512_60; i++) t[i - NLEN_512_60] = d[i];
            carry = t[NLEN_512_60 - 1] >> BASEBITS_512_60;
            t[NLEN_512_60 - 1] = t[NLEN_512_60 - 1] & BMASK_512_60; /* top word normalized */
        }
        return carry;
    }

    for (i = 0; i < NLEN_512_60 - 1; i++) b[i] = d[i];

    b[NLEN_512_60 - 1] = d[NLEN_512_60 - 1] & (((chunk)1 << m) - 1);

    if (t != b)
    {
        carry = (d[DNLEN_512_60 - 1] << (BASEBITS_512_60 - m));
        for (i = DNLEN_512_60 - 2; i >= NLEN_512_60 - 1; i--)
        {
            nw = (d[i] >> m) | carry;
            carry = (d[i] << (BASEBITS_512_60 - m))&BMASK_512_60;
            t[i - NLEN_512_60 + 1] = nw;
        }
    }
#ifdef DEBUG_NORM
    t[MPV_512_60] = 1;
    t[MNV_512_60] = 0;
    b[MPV_512_60] = 1;
    b[MNV_512_60] = 0;
#endif
    return carry;
}

/* you gotta keep the sign of carry! Look - no branching! */
/* Note that sign bit is needed to disambiguate between +ve and -ve values */
/* normalise BIG - force all digits < 2^BASEBITS */
chunk BIG_512_60_norm(BIG_512_60 a)
{
    int i;
    chunk d, carry;

    carry=a[0]>>BASEBITS_512_60;
    a[0]&=BMASK_512_60;

    for (i = 1; i < NLEN_512_60 - 1; i++)
    {
        d = a[i] + carry;
        a[i] = d & BMASK_512_60;
        carry = d >> BASEBITS_512_60;
    }
    a[NLEN_512_60 - 1] = (a[NLEN_512_60 - 1] + carry);

#ifdef DEBUG_NORM
    a[MPV_512_60] = 1;
    a[MNV_512_60] = 0;
#endif
    return (a[NLEN_512_60 - 1] >> ((8 * MODBYTES_512_60) % BASEBITS_512_60)); /* only used in ff.c */
}

void BIG_512_60_dnorm(DBIG_512_60 a)
{
    int i;
    chunk d, carry;

    carry=a[0]>>BASEBITS_512_60;
    a[0]&=BMASK_512_60;

    for (i = 1; i < DNLEN_512_60 - 1; i++)
    {
        d = a[i] + carry;
        a[i] = d & BMASK_512_60;
        carry = d >> BASEBITS_512_60;
    }
    a[DNLEN_512_60 - 1] = (a[DNLEN_512_60 - 1] + carry);
#ifdef DEBUG_NORM
    a[DMPV_512_60] = 1;
    a[DMNV_512_60] = 0;
#endif
}

/* Compare a and b. Return 1 for a>b, -1 for a<b, 0 for a==b */
/* a and b MUST be normalised before call */
/* sodium constant time implementation */

int BIG_512_60_comp(BIG_512_60 a, BIG_512_60 b)
{
    int i;
    chunk gt=0; chunk eq=1;
    for (i = NLEN_512_60-1; i>=0; i--)
    {
        gt |= ((b[i]-a[i]) >> BASEBITS_512_60) & eq;
        eq &= ((b[i]^a[i])-1) >> BASEBITS_512_60;
    }
    return (int)(gt+gt+eq-1);
}

int BIG_512_60_dcomp(DBIG_512_60 a, DBIG_512_60 b)
{
    int i;
    chunk gt=0; chunk eq=1;
    for (i = DNLEN_512_60-1; i>=0; i--)
    {
        gt |= ((b[i]-a[i]) >> BASEBITS_512_60) & eq;
        eq &= ((b[i]^a[i])-1) >> BASEBITS_512_60;
    }
    return (int)(gt+gt+eq-1);
}

/* return number of bits in a */
/* SU= 8 */
int BIG_512_60_nbits(BIG_512_60 a)
{
    int bts, k = NLEN_512_60 - 1;
    BIG_512_60 t;
    chunk c;
    BIG_512_60_copy(t, a);
    BIG_512_60_norm(t);
    while (k >= 0 && t[k] == 0) k--;
    if (k < 0) return 0;
    bts = BASEBITS_512_60 * k;
    c = t[k];
    while (c != 0)
    {
        c /= 2;
        bts++;
    }
    return bts;
}

/* SU= 8, Calculate number of bits in a DBIG - output normalised */
int BIG_512_60_dnbits(DBIG_512_60 a)
{
    int bts, k = DNLEN_512_60 - 1;
    DBIG_512_60 t;
    chunk c;
    BIG_512_60_dcopy(t, a);
    BIG_512_60_dnorm(t);
    while (k >= 0 && t[k] == 0) k--;
    if (k < 0) return 0;
    bts = BASEBITS_512_60 * k;
    c = t[k];
    while (c != 0)
    {
        c /= 2;
        bts++;
    }
    return bts;
}

void BIG_512_60_ctmod(BIG_512_60 b,BIG_512_60 m,int bd)
{
    int k=bd;
    BIG_512_60 r,c;
    BIG_512_60_copy(c,m);
    BIG_512_60_norm(b);

    BIG_512_60_shl(c,k);
    while (k>=0)
    {
        BIG_512_60_sub(r, b, c);
        BIG_512_60_norm(r);
        BIG_512_60_cmove(b, r, 1 - ((r[NLEN_512_60 - 1] >> (CHUNK - 1)) & 1));
        BIG_512_60_fshr(c, 1);
        k--;
    }
}

/* Set b=b mod c */
/* SU= 16 */
void BIG_512_60_mod(BIG_512_60 b, BIG_512_60 m)
{
    int k=BIG_512_60_nbits(b)-BIG_512_60_nbits(m);
    if (k<0) k=0;
    BIG_512_60_ctmod(b,m,k);
}

// Set a=b mod m in constant time (if bd is known at compile time)
// bd is Max number of bits in b - Actual number of bits in m
void BIG_512_60_ctdmod(BIG_512_60 a, DBIG_512_60 b, BIG_512_60 m, int bd)
{
    int k=bd;
    DBIG_512_60 c,r;
    BIG_512_60_dscopy(c,m);
    BIG_512_60_dnorm(b);

    BIG_512_60_dshl(c,k);
    while (k>=0)
    {
        BIG_512_60_dsub(r, b, c);
        BIG_512_60_dnorm(r);
        BIG_512_60_dcmove(b, r, 1 - ((r[DNLEN_512_60 - 1] >> (CHUNK - 1)) & 1));
        BIG_512_60_dshr(c, 1);
        k--;
    }
    BIG_512_60_sdcopy(a,b);
}


/* Set a=b mod m, b is destroyed. Slow but rarely used. */
void BIG_512_60_dmod(BIG_512_60 a, DBIG_512_60 b, BIG_512_60 m)
{
    int k=BIG_512_60_dnbits(b)-BIG_512_60_nbits(m);
    if (k<0) k=0;
    BIG_512_60_ctdmod(a,b,m,k);
}

// a=b/m  in constant time (if bd is known at compile time)
// bd is Max number of bits in b - Actual number of bits in m
void BIG_512_60_ctddiv(BIG_512_60 a,DBIG_512_60 b,BIG_512_60 m,int bd)
{
    int d,k=bd;
    DBIG_512_60 c,dr;
    BIG_512_60 e,r;
    BIG_512_60_dscopy(c,m);
    BIG_512_60_dnorm(b);

    BIG_512_60_zero(a);
    BIG_512_60_zero(e);
    BIG_512_60_inc(e, 1);

    BIG_512_60_shl(e,k);
    BIG_512_60_dshl(c,k);

    while (k >= 0)
    {
        BIG_512_60_dsub(dr, b, c);
        BIG_512_60_dnorm(dr);
        d = 1 - ((dr[DNLEN_512_60 - 1] >> (CHUNK - 1)) & 1);
        BIG_512_60_dcmove(b, dr, d);

        BIG_512_60_add(r, a, e);
        BIG_512_60_norm(r);
        BIG_512_60_cmove(a, r, d);

        BIG_512_60_dshr(c, 1);
        BIG_512_60_fshr(e, 1);
        k--;
    }
}

/* Set a=b/m,  b is destroyed. Slow but rarely used. */
void BIG_512_60_ddiv(BIG_512_60 a, DBIG_512_60 b, BIG_512_60 m)
{
    int k=BIG_512_60_dnbits(b)-BIG_512_60_nbits(m);
    if (k<0) k=0;
    BIG_512_60_ctddiv(a,b,m,k);
}

// a=a/m  in constant time (if bd is known at compile time)
// bd is Max number of bits in b - Actual number of bits in m
void BIG_512_60_ctsdiv(BIG_512_60 b,BIG_512_60 m,int bd)
{
    int d, k=bd;
    BIG_512_60 e,a,r,c;
    BIG_512_60_norm(b);
    BIG_512_60_copy(a,b);
    BIG_512_60_copy(c,m);
    BIG_512_60_zero(b);
    BIG_512_60_zero(e);
    BIG_512_60_inc(e, 1);

    BIG_512_60_shl(c,k);
    BIG_512_60_shl(e,k);

    while (k >= 0)
    {
        BIG_512_60_sub(r, a, c);
        BIG_512_60_norm(r);
        d = 1 - ((r[NLEN_512_60 - 1] >> (CHUNK - 1)) & 1);
        BIG_512_60_cmove(a, r, d);

        BIG_512_60_add(r, b, e);
        BIG_512_60_norm(r);
        BIG_512_60_cmove(b, r, d);

        BIG_512_60_fshr(c, 1);
        BIG_512_60_fshr(e, 1);

        k--;
    }
}

void BIG_512_60_sdiv(BIG_512_60 b, BIG_512_60 m)
{
    int k=BIG_512_60_nbits(b)-BIG_512_60_nbits(m);
    if (k<0) k=0;
    BIG_512_60_ctsdiv(b,m,k);
}

/* return LSB of a */
int BIG_512_60_parity(BIG_512_60 a)
{
    return a[0] % 2;
}

/* return n-th bit of a */
/* SU= 16 */
int BIG_512_60_bit(BIG_512_60 a, int n)
{
    return (int)((a[n / BASEBITS_512_60] & ((chunk)1 << (n % BASEBITS_512_60))) >> (n%BASEBITS_512_60));
//    if (a[n / BASEBITS_512_60] & ((chunk)1 << (n % BASEBITS_512_60))) return 1;
//    else return 0;
}

/* return last n bits of a, where n is small < BASEBITS */
/* SU= 16 */
int BIG_512_60_lastbits(BIG_512_60 a, int n)
{
    int msk = (1 << n) - 1;
    BIG_512_60_norm(a);
    return ((int)a[0])&msk;
}

/* get 8*MODBYTES size random number */
void BIG_512_60_random(BIG_512_60 m, csprng *rng)
{
    int i, b, j = 0, r = 0;
    int len = 8 * MODBYTES_512_60;

    BIG_512_60_zero(m);
    /* generate random BIG */
    for (i = 0; i < len; i++)
    {
        if (j == 0) r = RAND_byte(rng);
        else r >>= 1;
        b = r & 1;
        BIG_512_60_shl(m, 1);
        m[0] += b;
        j++;
        j &= 7;
    }

#ifdef DEBUG_NORM
    m[MPV_512_60] = 1;
    m[MNV_512_60] = 0;
#endif
}

/* get random BIG from rng, modulo q. Done one bit at a time, so its portable */

void BIG_512_60_randomnum(BIG_512_60 m, BIG_512_60 q, csprng *rng)
{
    int i, b, j = 0, r = 0;
    int n=2 * BIG_512_60_nbits(q);
    DBIG_512_60 d;
    BIG_512_60_dzero(d);
    /* generate random DBIG */
    for (i = 0; i < n; i++)
    {
        if (j == 0) r = RAND_byte(rng);
        else r >>= 1;
        b = r & 1;
        BIG_512_60_dshl(d, 1);
        d[0] += b;
        j++;
        j &= 7;
    }
    /* reduce modulo a BIG. Removes bias */
    BIG_512_60_dmod(m, d, q);
#ifdef DEBUG_NORM
    m[MPV_512_60] = 1;
    m[MNV_512_60] = 0;
#endif
}

/* create randum BIG less than r and less than trunc bits */
void BIG_512_60_randtrunc(BIG_512_60 s, BIG_512_60 r, int trunc, csprng *rng)
{
    BIG_512_60_randomnum(s, r, rng);
    if (BIG_512_60_nbits(r) > trunc)
        BIG_512_60_mod2m(s, trunc);
}


/* Set r=a*b mod m */
/* SU= 96 */
void BIG_512_60_modmul(BIG_512_60 r, BIG_512_60 a1, BIG_512_60 b1, BIG_512_60 m)
{
    DBIG_512_60 d;
    BIG_512_60 a, b;
    BIG_512_60_copy(a, a1);
    BIG_512_60_copy(b, b1);
    BIG_512_60_mod(a, m);
    BIG_512_60_mod(b, m);

    BIG_512_60_mul(d, a, b);
    BIG_512_60_ctdmod(r, d, m, BIG_512_60_nbits(m));
}

/* Set a=a*a mod m */
/* SU= 88 */
void BIG_512_60_modsqr(BIG_512_60 r, BIG_512_60 a1, BIG_512_60 m)
{
    DBIG_512_60 d;
    BIG_512_60 a;
    BIG_512_60_copy(a, a1);
    BIG_512_60_mod(a, m);
    BIG_512_60_sqr(d, a);
    BIG_512_60_ctdmod(r, d, m, BIG_512_60_nbits(m));
}

/* Set r=-a mod m */
/* SU= 16 */
void BIG_512_60_modneg(BIG_512_60 r, BIG_512_60 a1, BIG_512_60 m)
{
    BIG_512_60 a;
    BIG_512_60_copy(a, a1);
    BIG_512_60_mod(a, m);
    BIG_512_60_sub(r, m, a); BIG_512_60_norm(r);
}

/* Set r=a+b mod m */
void BIG_512_60_modadd(BIG_512_60 r, BIG_512_60 a1, BIG_512_60 b1, BIG_512_60 m)
{
    BIG_512_60 a, b;
    BIG_512_60_copy(a, a1);
    BIG_512_60_copy(b, b1);
    BIG_512_60_mod(a, m);
    BIG_512_60_mod(b, m);
    BIG_512_60_add(r,a,b); BIG_512_60_norm(r);
    BIG_512_60_ctmod(r,m,1);
}

/* Set a=a/b mod m */
/* SU= 136 */
void BIG_512_60_moddiv(BIG_512_60 r, BIG_512_60 a1, BIG_512_60 b1, BIG_512_60 m)
{
    DBIG_512_60 d;
    BIG_512_60 z;
    BIG_512_60 a, b;
    BIG_512_60_copy(a, a1);
    BIG_512_60_copy(b, b1);

    BIG_512_60_mod(a, m);
    BIG_512_60_invmodp(z, b, m);

    BIG_512_60_mul(d, a, z);
    BIG_512_60_ctdmod(r, d, m, BIG_512_60_nbits(m));
}

/* Get jacobi Symbol (a/p). Returns 0, 1 or -1 */
/* SU= 216 */
int BIG_512_60_jacobi(BIG_512_60 a, BIG_512_60 p)
{
    int n8, k, m = 0;
    BIG_512_60 t, x, n, zilch, one;
    BIG_512_60_one(one);
    BIG_512_60_zero(zilch);
    if (BIG_512_60_parity(p) == 0 || BIG_512_60_comp(a, zilch) == 0 || BIG_512_60_comp(p, one) <= 0) return 0;
    BIG_512_60_norm(a);
    BIG_512_60_copy(x, a);
    BIG_512_60_copy(n, p);
    BIG_512_60_mod(x, p);

    while (BIG_512_60_comp(n, one) > 0)
    {
        if (BIG_512_60_comp(x, zilch) == 0) return 0;
        n8 = BIG_512_60_lastbits(n, 3);
        k = 0;
        while (BIG_512_60_parity(x) == 0)
        {
            k++;
            BIG_512_60_shr(x, 1);
        }
        if (k % 2 == 1) m += (n8 * n8 - 1) / 8;
        m += (n8 - 1) * (BIG_512_60_lastbits(x, 2) - 1) / 4;
        BIG_512_60_copy(t, n);

        BIG_512_60_mod(t, x);
        BIG_512_60_copy(n, x);
        BIG_512_60_copy(x, t);
        m %= 2;

    }
    if (m == 0) return 1;
    else return -1;
}

/* Arazi and Qi inversion mod 256 */
static int invmod256(int a)
{
    int U, t1, t2, b, c;
    t1 = 0;
    c = (a >> 1) & 1;
    t1 += c;
    t1 &= 1;
    t1 = 2 - t1;
    t1 <<= 1;
    U = t1 + 1;

// i=2
    b = a & 3;
    t1 = U * b;
    t1 >>= 2;
    c = (a >> 2) & 3;
    t2 = (U * c) & 3;
    t1 += t2;
    t1 *= U;
    t1 &= 3;
    t1 = 4 - t1;
    t1 <<= 2;
    U += t1;

// i=4
    b = a & 15;
    t1 = U * b;
    t1 >>= 4;
    c = (a >> 4) & 15;
    t2 = (U * c) & 15;
    t1 += t2;
    t1 *= U;
    t1 &= 15;
    t1 = 16 - t1;
    t1 <<= 4;
    U += t1;

    return U;
}

/* a=1/a mod 2^BIGBITS. This is very fast! */
void BIG_512_60_invmod2m(BIG_512_60 a)
{
    int i;
    BIG_512_60 U, t1, b, c;
    BIG_512_60_zero(U);
    BIG_512_60_inc(U, invmod256(BIG_512_60_lastbits(a, 8)));
    for (i = 8; i < BIGBITS_512_60; i <<= 1)
    {
        BIG_512_60_norm(U);
        BIG_512_60_copy(b, a);
        BIG_512_60_mod2m(b, i);  // bottom i bits of a

        BIG_512_60_smul(t1, U, b);
        BIG_512_60_shr(t1, i); // top i bits of U*b

        BIG_512_60_copy(c, a);
        BIG_512_60_shr(c, i);
        BIG_512_60_mod2m(c, i); // top i bits of a

        BIG_512_60_smul(b, U, c);
        BIG_512_60_mod2m(b, i); // bottom i bits of U*c

        BIG_512_60_add(t1, t1, b);
        BIG_512_60_norm(t1);
        BIG_512_60_smul(b, t1, U);
        BIG_512_60_copy(t1, b); // (t1+b)*U
        BIG_512_60_mod2m(t1, i);               // bottom i bits of (t1+b)*U

        BIG_512_60_one(b);
        BIG_512_60_shl(b, i);
        BIG_512_60_sub(t1, b, t1);
        BIG_512_60_norm(t1);

        BIG_512_60_shl(t1, i);

        BIG_512_60_add(U, U, t1);
    }
    BIG_512_60_copy(a, U);
    BIG_512_60_norm(a);
    BIG_512_60_mod2m(a, BIGBITS_512_60);
}

/* Set r=1/a mod p. Binary method */
/* SU= 240 */
void BIG_512_60_invmodp(BIG_512_60 r, BIG_512_60 a, BIG_512_60 p)
{
    BIG_512_60 u, v, x1, x2, t, one;

    BIG_512_60_mod(a, p);
    if (BIG_512_60_iszilch(a))
    {
        BIG_512_60_zero(r);
        return;
    }

    BIG_512_60_copy(u, a);
    BIG_512_60_copy(v, p);
    BIG_512_60_one(one);
    BIG_512_60_copy(x1, one);
    BIG_512_60_zero(x2);

    while (BIG_512_60_comp(u, one) != 0 && BIG_512_60_comp(v, one) != 0)
    {
        while (BIG_512_60_parity(u) == 0)
        {
            BIG_512_60_fshr(u, 1);
            BIG_512_60_add(t,x1,p);
            BIG_512_60_cmove(x1,t,BIG_512_60_parity(x1));
            BIG_512_60_norm(x1);
            BIG_512_60_fshr(x1,1);
        }
        while (BIG_512_60_parity(v) == 0)
        {
            BIG_512_60_fshr(v, 1);
            BIG_512_60_add(t,x2,p);
            BIG_512_60_cmove(x2,t,BIG_512_60_parity(x2));
            BIG_512_60_norm(x2);
            BIG_512_60_fshr(x2,1);
        }
        if (BIG_512_60_comp(u, v) >= 0)
        {
            BIG_512_60_sub(u, u, v);
            BIG_512_60_norm(u);
            BIG_512_60_add(t,x1,p);
            BIG_512_60_cmove(x1,t,(BIG_512_60_comp(x1,x2)>>1)&1); /* move if x1<x2 */
            BIG_512_60_sub(x1,x1,x2);
            BIG_512_60_norm(x1);
        }
        else
        {
            BIG_512_60_sub(v, v, u);
            BIG_512_60_norm(v);
            BIG_512_60_add(t,x2,p);
            BIG_512_60_cmove(x2,t,(BIG_512_60_comp(x2,x1)>>1)&1); /* move if x2<x1 */
            BIG_512_60_sub(x2,x2,x1);
            BIG_512_60_norm(x2);
        }
    }
    BIG_512_60_copy(r,x1);
    BIG_512_60_cmove(r,x2,BIG_512_60_comp(u,one)&1);
}

/* set x = x mod 2^m */
void BIG_512_60_mod2m(BIG_512_60 x, int m)
{
    int i, wd, bt;
    chunk msk;
    BIG_512_60_norm(x);

    wd = m / BASEBITS_512_60;
    bt = m % BASEBITS_512_60;
    msk = ((chunk)1 << bt) - 1;
    x[wd] &= msk;
    for (i = wd + 1; i < NLEN_512_60; i++) x[i] = 0;
}

// new
/* Convert to DBIG number from byte array of given length */
void BIG_512_60_dfromBytesLen(DBIG_512_60 a, char *b, int s)
{
    int i, len = s;
    BIG_512_60_dzero(a);

    for (i = 0; i < len; i++)
    {
        BIG_512_60_dshl(a, 8);
        a[0] += (int)(unsigned char)b[i];
    }
#ifdef DEBUG_NORM
    a[DMPV_512_60] = 1;
    a[DMNV_512_60] = 0;
#endif
}
