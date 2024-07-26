"""
"""

from sys import version_info as _swig_python_version_info
if _swig_python_version_info < (2, 7, 0):
    raise RuntimeError("Python 2.7 or later required")

# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_allins
else:
    import _ida_allins

try:
    import builtins as __builtin__
except ImportError:
    import __builtin__

def _swig_repr(self):
    try:
        strthis = "proxy of " + self.this.__repr__()
    except __builtin__.Exception:
        strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)


def _swig_setattr_nondynamic_instance_variable(set):
    def set_instance_attr(self, name, value):
        if name == "thisown":
            self.this.own(value)
        elif name == "this":
            set(self, name, value)
        elif hasattr(self, name) and isinstance(getattr(type(self), name), property):
            set(self, name, value)
        else:
            raise AttributeError("You cannot add instance attributes to %s" % self)
    return set_instance_attr


def _swig_setattr_nondynamic_class_variable(set):
    def set_class_attr(cls, name, value):
        if hasattr(cls, name) and not isinstance(getattr(cls, name), property):
            set(cls, name, value)
        else:
            raise AttributeError("You cannot add class attributes to %s" % cls)
    return set_class_attr


def _swig_add_metaclass(metaclass):
    """Class decorator for adding a metaclass to a SWIG wrapped class - a slimmed down version of six.add_metaclass"""
    def wrapper(cls):
        return metaclass(cls.__name__, cls.__bases__, cls.__dict__.copy())
    return wrapper


class _SwigNonDynamicMeta(type):
    """Meta class to enforce nondynamic attributes (no new attributes) for a class"""
    __setattr__ = _swig_setattr_nondynamic_class_variable(type.__setattr__)


import weakref

SWIG_PYTHON_LEGACY_BOOL = _ida_allins.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi

NN_null = _ida_allins.NN_null

NN_aaa = _ida_allins.NN_aaa

NN_aad = _ida_allins.NN_aad

NN_aam = _ida_allins.NN_aam

NN_aas = _ida_allins.NN_aas

NN_adc = _ida_allins.NN_adc

NN_add = _ida_allins.NN_add

NN_and = _ida_allins.NN_and

NN_arpl = _ida_allins.NN_arpl

NN_bound = _ida_allins.NN_bound

NN_bsf = _ida_allins.NN_bsf

NN_bsr = _ida_allins.NN_bsr

NN_bt = _ida_allins.NN_bt

NN_btc = _ida_allins.NN_btc

NN_btr = _ida_allins.NN_btr

NN_bts = _ida_allins.NN_bts

NN_call = _ida_allins.NN_call

NN_callfi = _ida_allins.NN_callfi

NN_callni = _ida_allins.NN_callni

NN_cbw = _ida_allins.NN_cbw

NN_cwde = _ida_allins.NN_cwde

NN_cdqe = _ida_allins.NN_cdqe

NN_clc = _ida_allins.NN_clc

NN_cld = _ida_allins.NN_cld

NN_cli = _ida_allins.NN_cli

NN_clts = _ida_allins.NN_clts

NN_cmc = _ida_allins.NN_cmc

NN_cmp = _ida_allins.NN_cmp

NN_cmps = _ida_allins.NN_cmps

NN_cwd = _ida_allins.NN_cwd

NN_cdq = _ida_allins.NN_cdq

NN_cqo = _ida_allins.NN_cqo

NN_daa = _ida_allins.NN_daa

NN_das = _ida_allins.NN_das

NN_dec = _ida_allins.NN_dec

NN_div = _ida_allins.NN_div

NN_enterw = _ida_allins.NN_enterw

NN_enter = _ida_allins.NN_enter

NN_enterd = _ida_allins.NN_enterd

NN_enterq = _ida_allins.NN_enterq

NN_hlt = _ida_allins.NN_hlt

NN_idiv = _ida_allins.NN_idiv

NN_imul = _ida_allins.NN_imul

NN_in = _ida_allins.NN_in

NN_inc = _ida_allins.NN_inc

NN_ins = _ida_allins.NN_ins

NN_int = _ida_allins.NN_int

NN_into = _ida_allins.NN_into

NN_int3 = _ida_allins.NN_int3

NN_iretw = _ida_allins.NN_iretw

NN_iret = _ida_allins.NN_iret

NN_iretd = _ida_allins.NN_iretd

NN_iretq = _ida_allins.NN_iretq

NN_ja = _ida_allins.NN_ja

NN_jae = _ida_allins.NN_jae

NN_jb = _ida_allins.NN_jb

NN_jbe = _ida_allins.NN_jbe

NN_jc = _ida_allins.NN_jc

NN_jcxz = _ida_allins.NN_jcxz

NN_jecxz = _ida_allins.NN_jecxz

NN_jrcxz = _ida_allins.NN_jrcxz

NN_je = _ida_allins.NN_je

NN_jg = _ida_allins.NN_jg

NN_jge = _ida_allins.NN_jge

NN_jl = _ida_allins.NN_jl

NN_jle = _ida_allins.NN_jle

NN_jna = _ida_allins.NN_jna

NN_jnae = _ida_allins.NN_jnae

NN_jnb = _ida_allins.NN_jnb

NN_jnbe = _ida_allins.NN_jnbe

NN_jnc = _ida_allins.NN_jnc

NN_jne = _ida_allins.NN_jne

NN_jng = _ida_allins.NN_jng

NN_jnge = _ida_allins.NN_jnge

NN_jnl = _ida_allins.NN_jnl

NN_jnle = _ida_allins.NN_jnle

NN_jno = _ida_allins.NN_jno

NN_jnp = _ida_allins.NN_jnp

NN_jns = _ida_allins.NN_jns

NN_jnz = _ida_allins.NN_jnz

NN_jo = _ida_allins.NN_jo

NN_jp = _ida_allins.NN_jp

NN_jpe = _ida_allins.NN_jpe

NN_jpo = _ida_allins.NN_jpo

NN_js = _ida_allins.NN_js

NN_jz = _ida_allins.NN_jz

NN_jmp = _ida_allins.NN_jmp

NN_jmpfi = _ida_allins.NN_jmpfi

NN_jmpni = _ida_allins.NN_jmpni

NN_jmpshort = _ida_allins.NN_jmpshort

NN_lahf = _ida_allins.NN_lahf

NN_lar = _ida_allins.NN_lar

NN_lea = _ida_allins.NN_lea

NN_leavew = _ida_allins.NN_leavew

NN_leave = _ida_allins.NN_leave

NN_leaved = _ida_allins.NN_leaved

NN_leaveq = _ida_allins.NN_leaveq

NN_lgdt = _ida_allins.NN_lgdt

NN_lidt = _ida_allins.NN_lidt

NN_lgs = _ida_allins.NN_lgs

NN_lss = _ida_allins.NN_lss

NN_lds = _ida_allins.NN_lds

NN_les = _ida_allins.NN_les

NN_lfs = _ida_allins.NN_lfs

NN_lldt = _ida_allins.NN_lldt

NN_lmsw = _ida_allins.NN_lmsw

NN_lock = _ida_allins.NN_lock

NN_lods = _ida_allins.NN_lods

NN_loopw = _ida_allins.NN_loopw

NN_loop = _ida_allins.NN_loop

NN_loopd = _ida_allins.NN_loopd

NN_loopq = _ida_allins.NN_loopq

NN_loopwe = _ida_allins.NN_loopwe

NN_loope = _ida_allins.NN_loope

NN_loopde = _ida_allins.NN_loopde

NN_loopqe = _ida_allins.NN_loopqe

NN_loopwne = _ida_allins.NN_loopwne

NN_loopne = _ida_allins.NN_loopne

NN_loopdne = _ida_allins.NN_loopdne

NN_loopqne = _ida_allins.NN_loopqne

NN_lsl = _ida_allins.NN_lsl

NN_ltr = _ida_allins.NN_ltr

NN_mov = _ida_allins.NN_mov

NN_movsp = _ida_allins.NN_movsp

NN_movs = _ida_allins.NN_movs

NN_movsx = _ida_allins.NN_movsx

NN_movzx = _ida_allins.NN_movzx

NN_mul = _ida_allins.NN_mul

NN_neg = _ida_allins.NN_neg

NN_nop = _ida_allins.NN_nop

NN_not = _ida_allins.NN_not

NN_or = _ida_allins.NN_or

NN_out = _ida_allins.NN_out

NN_outs = _ida_allins.NN_outs

NN_pop = _ida_allins.NN_pop

NN_popaw = _ida_allins.NN_popaw

NN_popa = _ida_allins.NN_popa

NN_popad = _ida_allins.NN_popad

NN_popaq = _ida_allins.NN_popaq

NN_popfw = _ida_allins.NN_popfw

NN_popf = _ida_allins.NN_popf

NN_popfd = _ida_allins.NN_popfd

NN_popfq = _ida_allins.NN_popfq

NN_push = _ida_allins.NN_push

NN_pushaw = _ida_allins.NN_pushaw

NN_pusha = _ida_allins.NN_pusha

NN_pushad = _ida_allins.NN_pushad

NN_pushaq = _ida_allins.NN_pushaq

NN_pushfw = _ida_allins.NN_pushfw

NN_pushf = _ida_allins.NN_pushf

NN_pushfd = _ida_allins.NN_pushfd

NN_pushfq = _ida_allins.NN_pushfq

NN_rcl = _ida_allins.NN_rcl

NN_rcr = _ida_allins.NN_rcr

NN_rol = _ida_allins.NN_rol

NN_ror = _ida_allins.NN_ror

NN_rep = _ida_allins.NN_rep

NN_repe = _ida_allins.NN_repe

NN_repne = _ida_allins.NN_repne

NN_retn = _ida_allins.NN_retn

NN_retf = _ida_allins.NN_retf

NN_sahf = _ida_allins.NN_sahf

NN_sal = _ida_allins.NN_sal

NN_sar = _ida_allins.NN_sar

NN_shl = _ida_allins.NN_shl

NN_shr = _ida_allins.NN_shr

NN_sbb = _ida_allins.NN_sbb

NN_scas = _ida_allins.NN_scas

NN_seta = _ida_allins.NN_seta

NN_setae = _ida_allins.NN_setae

NN_setb = _ida_allins.NN_setb

NN_setbe = _ida_allins.NN_setbe

NN_setc = _ida_allins.NN_setc

NN_sete = _ida_allins.NN_sete

NN_setg = _ida_allins.NN_setg

NN_setge = _ida_allins.NN_setge

NN_setl = _ida_allins.NN_setl

NN_setle = _ida_allins.NN_setle

NN_setna = _ida_allins.NN_setna

NN_setnae = _ida_allins.NN_setnae

NN_setnb = _ida_allins.NN_setnb

NN_setnbe = _ida_allins.NN_setnbe

NN_setnc = _ida_allins.NN_setnc

NN_setne = _ida_allins.NN_setne

NN_setng = _ida_allins.NN_setng

NN_setnge = _ida_allins.NN_setnge

NN_setnl = _ida_allins.NN_setnl

NN_setnle = _ida_allins.NN_setnle

NN_setno = _ida_allins.NN_setno

NN_setnp = _ida_allins.NN_setnp

NN_setns = _ida_allins.NN_setns

NN_setnz = _ida_allins.NN_setnz

NN_seto = _ida_allins.NN_seto

NN_setp = _ida_allins.NN_setp

NN_setpe = _ida_allins.NN_setpe

NN_setpo = _ida_allins.NN_setpo

NN_sets = _ida_allins.NN_sets

NN_setz = _ida_allins.NN_setz

NN_sgdt = _ida_allins.NN_sgdt

NN_sidt = _ida_allins.NN_sidt

NN_shld = _ida_allins.NN_shld

NN_shrd = _ida_allins.NN_shrd

NN_sldt = _ida_allins.NN_sldt

NN_smsw = _ida_allins.NN_smsw

NN_stc = _ida_allins.NN_stc

NN_std = _ida_allins.NN_std

NN_sti = _ida_allins.NN_sti

NN_stos = _ida_allins.NN_stos

NN_str = _ida_allins.NN_str

NN_sub = _ida_allins.NN_sub

NN_test = _ida_allins.NN_test

NN_verr = _ida_allins.NN_verr

NN_verw = _ida_allins.NN_verw

NN_wait = _ida_allins.NN_wait

NN_xchg = _ida_allins.NN_xchg

NN_xlat = _ida_allins.NN_xlat

NN_xor = _ida_allins.NN_xor

NN_cmpxchg = _ida_allins.NN_cmpxchg

NN_bswap = _ida_allins.NN_bswap

NN_xadd = _ida_allins.NN_xadd

NN_invd = _ida_allins.NN_invd

NN_wbinvd = _ida_allins.NN_wbinvd

NN_invlpg = _ida_allins.NN_invlpg

NN_rdmsr = _ida_allins.NN_rdmsr

NN_wrmsr = _ida_allins.NN_wrmsr

NN_cpuid = _ida_allins.NN_cpuid

NN_cmpxchg8b = _ida_allins.NN_cmpxchg8b

NN_rdtsc = _ida_allins.NN_rdtsc

NN_rsm = _ida_allins.NN_rsm

NN_cmova = _ida_allins.NN_cmova

NN_cmovb = _ida_allins.NN_cmovb

NN_cmovbe = _ida_allins.NN_cmovbe

NN_cmovg = _ida_allins.NN_cmovg

NN_cmovge = _ida_allins.NN_cmovge

NN_cmovl = _ida_allins.NN_cmovl

NN_cmovle = _ida_allins.NN_cmovle

NN_cmovnb = _ida_allins.NN_cmovnb

NN_cmovno = _ida_allins.NN_cmovno

NN_cmovnp = _ida_allins.NN_cmovnp

NN_cmovns = _ida_allins.NN_cmovns

NN_cmovnz = _ida_allins.NN_cmovnz

NN_cmovo = _ida_allins.NN_cmovo

NN_cmovp = _ida_allins.NN_cmovp

NN_cmovs = _ida_allins.NN_cmovs

NN_cmovz = _ida_allins.NN_cmovz

NN_fcmovb = _ida_allins.NN_fcmovb

NN_fcmove = _ida_allins.NN_fcmove

NN_fcmovbe = _ida_allins.NN_fcmovbe

NN_fcmovu = _ida_allins.NN_fcmovu

NN_fcmovnb = _ida_allins.NN_fcmovnb

NN_fcmovne = _ida_allins.NN_fcmovne

NN_fcmovnbe = _ida_allins.NN_fcmovnbe

NN_fcmovnu = _ida_allins.NN_fcmovnu

NN_fcomi = _ida_allins.NN_fcomi

NN_fucomi = _ida_allins.NN_fucomi

NN_fcomip = _ida_allins.NN_fcomip

NN_fucomip = _ida_allins.NN_fucomip

NN_rdpmc = _ida_allins.NN_rdpmc

NN_fld = _ida_allins.NN_fld

NN_fst = _ida_allins.NN_fst

NN_fstp = _ida_allins.NN_fstp

NN_fxch = _ida_allins.NN_fxch

NN_fild = _ida_allins.NN_fild

NN_fist = _ida_allins.NN_fist

NN_fistp = _ida_allins.NN_fistp

NN_fbld = _ida_allins.NN_fbld

NN_fbstp = _ida_allins.NN_fbstp

NN_fadd = _ida_allins.NN_fadd

NN_faddp = _ida_allins.NN_faddp

NN_fiadd = _ida_allins.NN_fiadd

NN_fsub = _ida_allins.NN_fsub

NN_fsubp = _ida_allins.NN_fsubp

NN_fisub = _ida_allins.NN_fisub

NN_fsubr = _ida_allins.NN_fsubr

NN_fsubrp = _ida_allins.NN_fsubrp

NN_fisubr = _ida_allins.NN_fisubr

NN_fmul = _ida_allins.NN_fmul

NN_fmulp = _ida_allins.NN_fmulp

NN_fimul = _ida_allins.NN_fimul

NN_fdiv = _ida_allins.NN_fdiv

NN_fdivp = _ida_allins.NN_fdivp

NN_fidiv = _ida_allins.NN_fidiv

NN_fdivr = _ida_allins.NN_fdivr

NN_fdivrp = _ida_allins.NN_fdivrp

NN_fidivr = _ida_allins.NN_fidivr

NN_fsqrt = _ida_allins.NN_fsqrt

NN_fscale = _ida_allins.NN_fscale

NN_fprem = _ida_allins.NN_fprem

NN_frndint = _ida_allins.NN_frndint

NN_fxtract = _ida_allins.NN_fxtract

NN_fabs = _ida_allins.NN_fabs

NN_fchs = _ida_allins.NN_fchs

NN_fcom = _ida_allins.NN_fcom

NN_fcomp = _ida_allins.NN_fcomp

NN_fcompp = _ida_allins.NN_fcompp

NN_ficom = _ida_allins.NN_ficom

NN_ficomp = _ida_allins.NN_ficomp

NN_ftst = _ida_allins.NN_ftst

NN_fxam = _ida_allins.NN_fxam

NN_fptan = _ida_allins.NN_fptan

NN_fpatan = _ida_allins.NN_fpatan

NN_f2xm1 = _ida_allins.NN_f2xm1

NN_fyl2x = _ida_allins.NN_fyl2x

NN_fyl2xp1 = _ida_allins.NN_fyl2xp1

NN_fldz = _ida_allins.NN_fldz

NN_fld1 = _ida_allins.NN_fld1

NN_fldpi = _ida_allins.NN_fldpi

NN_fldl2t = _ida_allins.NN_fldl2t

NN_fldl2e = _ida_allins.NN_fldl2e

NN_fldlg2 = _ida_allins.NN_fldlg2

NN_fldln2 = _ida_allins.NN_fldln2

NN_finit = _ida_allins.NN_finit

NN_fninit = _ida_allins.NN_fninit

NN_fsetpm = _ida_allins.NN_fsetpm

NN_fldcw = _ida_allins.NN_fldcw

NN_fstcw = _ida_allins.NN_fstcw

NN_fnstcw = _ida_allins.NN_fnstcw

NN_fstsw = _ida_allins.NN_fstsw

NN_fnstsw = _ida_allins.NN_fnstsw

NN_fclex = _ida_allins.NN_fclex

NN_fnclex = _ida_allins.NN_fnclex

NN_fstenv = _ida_allins.NN_fstenv

NN_fnstenv = _ida_allins.NN_fnstenv

NN_fldenv = _ida_allins.NN_fldenv

NN_fsave = _ida_allins.NN_fsave

NN_fnsave = _ida_allins.NN_fnsave

NN_frstor = _ida_allins.NN_frstor

NN_fincstp = _ida_allins.NN_fincstp

NN_fdecstp = _ida_allins.NN_fdecstp

NN_ffree = _ida_allins.NN_ffree

NN_fnop = _ida_allins.NN_fnop

NN_feni = _ida_allins.NN_feni

NN_fneni = _ida_allins.NN_fneni

NN_fdisi = _ida_allins.NN_fdisi

NN_fndisi = _ida_allins.NN_fndisi

NN_fprem1 = _ida_allins.NN_fprem1

NN_fsincos = _ida_allins.NN_fsincos

NN_fsin = _ida_allins.NN_fsin

NN_fcos = _ida_allins.NN_fcos

NN_fucom = _ida_allins.NN_fucom

NN_fucomp = _ida_allins.NN_fucomp

NN_fucompp = _ida_allins.NN_fucompp

NN_setalc = _ida_allins.NN_setalc

NN_svdc = _ida_allins.NN_svdc

NN_rsdc = _ida_allins.NN_rsdc

NN_svldt = _ida_allins.NN_svldt

NN_rsldt = _ida_allins.NN_rsldt

NN_svts = _ida_allins.NN_svts

NN_rsts = _ida_allins.NN_rsts

NN_icebp = _ida_allins.NN_icebp

NN_loadall = _ida_allins.NN_loadall

NN_emms = _ida_allins.NN_emms

NN_movd = _ida_allins.NN_movd

NN_movq = _ida_allins.NN_movq

NN_packsswb = _ida_allins.NN_packsswb

NN_packssdw = _ida_allins.NN_packssdw

NN_packuswb = _ida_allins.NN_packuswb

NN_paddb = _ida_allins.NN_paddb

NN_paddw = _ida_allins.NN_paddw

NN_paddd = _ida_allins.NN_paddd

NN_paddsb = _ida_allins.NN_paddsb

NN_paddsw = _ida_allins.NN_paddsw

NN_paddusb = _ida_allins.NN_paddusb

NN_paddusw = _ida_allins.NN_paddusw

NN_pand = _ida_allins.NN_pand

NN_pandn = _ida_allins.NN_pandn

NN_pcmpeqb = _ida_allins.NN_pcmpeqb

NN_pcmpeqw = _ida_allins.NN_pcmpeqw

NN_pcmpeqd = _ida_allins.NN_pcmpeqd

NN_pcmpgtb = _ida_allins.NN_pcmpgtb

NN_pcmpgtw = _ida_allins.NN_pcmpgtw

NN_pcmpgtd = _ida_allins.NN_pcmpgtd

NN_pmaddwd = _ida_allins.NN_pmaddwd

NN_pmulhw = _ida_allins.NN_pmulhw

NN_pmullw = _ida_allins.NN_pmullw

NN_por = _ida_allins.NN_por

NN_psllw = _ida_allins.NN_psllw

NN_pslld = _ida_allins.NN_pslld

NN_psllq = _ida_allins.NN_psllq

NN_psraw = _ida_allins.NN_psraw

NN_psrad = _ida_allins.NN_psrad

NN_psrlw = _ida_allins.NN_psrlw

NN_psrld = _ida_allins.NN_psrld

NN_psrlq = _ida_allins.NN_psrlq

NN_psubb = _ida_allins.NN_psubb

NN_psubw = _ida_allins.NN_psubw

NN_psubd = _ida_allins.NN_psubd

NN_psubsb = _ida_allins.NN_psubsb

NN_psubsw = _ida_allins.NN_psubsw

NN_psubusb = _ida_allins.NN_psubusb

NN_psubusw = _ida_allins.NN_psubusw

NN_punpckhbw = _ida_allins.NN_punpckhbw

NN_punpckhwd = _ida_allins.NN_punpckhwd

NN_punpckhdq = _ida_allins.NN_punpckhdq

NN_punpcklbw = _ida_allins.NN_punpcklbw

NN_punpcklwd = _ida_allins.NN_punpcklwd

NN_punpckldq = _ida_allins.NN_punpckldq

NN_pxor = _ida_allins.NN_pxor

NN_fxsave = _ida_allins.NN_fxsave

NN_fxrstor = _ida_allins.NN_fxrstor

NN_sysenter = _ida_allins.NN_sysenter

NN_sysexit = _ida_allins.NN_sysexit

NN_pavgusb = _ida_allins.NN_pavgusb

NN_pfadd = _ida_allins.NN_pfadd

NN_pfsub = _ida_allins.NN_pfsub

NN_pfsubr = _ida_allins.NN_pfsubr

NN_pfacc = _ida_allins.NN_pfacc

NN_pfcmpge = _ida_allins.NN_pfcmpge

NN_pfcmpgt = _ida_allins.NN_pfcmpgt

NN_pfcmpeq = _ida_allins.NN_pfcmpeq

NN_pfmin = _ida_allins.NN_pfmin

NN_pfmax = _ida_allins.NN_pfmax

NN_pi2fd = _ida_allins.NN_pi2fd

NN_pf2id = _ida_allins.NN_pf2id

NN_pfrcp = _ida_allins.NN_pfrcp

NN_pfrsqrt = _ida_allins.NN_pfrsqrt

NN_pfmul = _ida_allins.NN_pfmul

NN_pfrcpit1 = _ida_allins.NN_pfrcpit1

NN_pfrsqit1 = _ida_allins.NN_pfrsqit1

NN_pfrcpit2 = _ida_allins.NN_pfrcpit2

NN_pmulhrw = _ida_allins.NN_pmulhrw

NN_femms = _ida_allins.NN_femms

NN_prefetch = _ida_allins.NN_prefetch

NN_prefetchw = _ida_allins.NN_prefetchw

NN_addps = _ida_allins.NN_addps

NN_addss = _ida_allins.NN_addss

NN_andnps = _ida_allins.NN_andnps

NN_andps = _ida_allins.NN_andps

NN_cmpps = _ida_allins.NN_cmpps

NN_cmpss = _ida_allins.NN_cmpss

NN_comiss = _ida_allins.NN_comiss

NN_cvtpi2ps = _ida_allins.NN_cvtpi2ps

NN_cvtps2pi = _ida_allins.NN_cvtps2pi

NN_cvtsi2ss = _ida_allins.NN_cvtsi2ss

NN_cvtss2si = _ida_allins.NN_cvtss2si

NN_cvttps2pi = _ida_allins.NN_cvttps2pi

NN_cvttss2si = _ida_allins.NN_cvttss2si

NN_divps = _ida_allins.NN_divps

NN_divss = _ida_allins.NN_divss

NN_ldmxcsr = _ida_allins.NN_ldmxcsr

NN_maxps = _ida_allins.NN_maxps

NN_maxss = _ida_allins.NN_maxss

NN_minps = _ida_allins.NN_minps

NN_minss = _ida_allins.NN_minss

NN_movaps = _ida_allins.NN_movaps

NN_movhlps = _ida_allins.NN_movhlps

NN_movhps = _ida_allins.NN_movhps

NN_movlhps = _ida_allins.NN_movlhps

NN_movlps = _ida_allins.NN_movlps

NN_movmskps = _ida_allins.NN_movmskps

NN_movss = _ida_allins.NN_movss

NN_movups = _ida_allins.NN_movups

NN_mulps = _ida_allins.NN_mulps

NN_mulss = _ida_allins.NN_mulss

NN_orps = _ida_allins.NN_orps

NN_rcpps = _ida_allins.NN_rcpps

NN_rcpss = _ida_allins.NN_rcpss

NN_rsqrtps = _ida_allins.NN_rsqrtps

NN_rsqrtss = _ida_allins.NN_rsqrtss

NN_shufps = _ida_allins.NN_shufps

NN_sqrtps = _ida_allins.NN_sqrtps

NN_sqrtss = _ida_allins.NN_sqrtss

NN_stmxcsr = _ida_allins.NN_stmxcsr

NN_subps = _ida_allins.NN_subps

NN_subss = _ida_allins.NN_subss

NN_ucomiss = _ida_allins.NN_ucomiss

NN_unpckhps = _ida_allins.NN_unpckhps

NN_unpcklps = _ida_allins.NN_unpcklps

NN_xorps = _ida_allins.NN_xorps

NN_pavgb = _ida_allins.NN_pavgb

NN_pavgw = _ida_allins.NN_pavgw

NN_pextrw = _ida_allins.NN_pextrw

NN_pinsrw = _ida_allins.NN_pinsrw

NN_pmaxsw = _ida_allins.NN_pmaxsw

NN_pmaxub = _ida_allins.NN_pmaxub

NN_pminsw = _ida_allins.NN_pminsw

NN_pminub = _ida_allins.NN_pminub

NN_pmovmskb = _ida_allins.NN_pmovmskb

NN_pmulhuw = _ida_allins.NN_pmulhuw

NN_psadbw = _ida_allins.NN_psadbw

NN_pshufw = _ida_allins.NN_pshufw

NN_maskmovq = _ida_allins.NN_maskmovq

NN_movntps = _ida_allins.NN_movntps

NN_movntq = _ida_allins.NN_movntq

NN_prefetcht0 = _ida_allins.NN_prefetcht0

NN_prefetcht1 = _ida_allins.NN_prefetcht1

NN_prefetcht2 = _ida_allins.NN_prefetcht2

NN_prefetchnta = _ida_allins.NN_prefetchnta

NN_sfence = _ida_allins.NN_sfence

NN_cmpeqps = _ida_allins.NN_cmpeqps

NN_cmpltps = _ida_allins.NN_cmpltps

NN_cmpleps = _ida_allins.NN_cmpleps

NN_cmpunordps = _ida_allins.NN_cmpunordps

NN_cmpneqps = _ida_allins.NN_cmpneqps

NN_cmpnltps = _ida_allins.NN_cmpnltps

NN_cmpnleps = _ida_allins.NN_cmpnleps

NN_cmpordps = _ida_allins.NN_cmpordps

NN_cmpeqss = _ida_allins.NN_cmpeqss

NN_cmpltss = _ida_allins.NN_cmpltss

NN_cmpless = _ida_allins.NN_cmpless

NN_cmpunordss = _ida_allins.NN_cmpunordss

NN_cmpneqss = _ida_allins.NN_cmpneqss

NN_cmpnltss = _ida_allins.NN_cmpnltss

NN_cmpnless = _ida_allins.NN_cmpnless

NN_cmpordss = _ida_allins.NN_cmpordss

NN_pf2iw = _ida_allins.NN_pf2iw

NN_pfnacc = _ida_allins.NN_pfnacc

NN_pfpnacc = _ida_allins.NN_pfpnacc

NN_pi2fw = _ida_allins.NN_pi2fw

NN_pswapd = _ida_allins.NN_pswapd

NN_fstp1 = _ida_allins.NN_fstp1

NN_fcom2 = _ida_allins.NN_fcom2

NN_fcomp3 = _ida_allins.NN_fcomp3

NN_fxch4 = _ida_allins.NN_fxch4

NN_fcomp5 = _ida_allins.NN_fcomp5

NN_ffreep = _ida_allins.NN_ffreep

NN_fxch7 = _ida_allins.NN_fxch7

NN_fstp8 = _ida_allins.NN_fstp8

NN_fstp9 = _ida_allins.NN_fstp9

NN_addpd = _ida_allins.NN_addpd

NN_addsd = _ida_allins.NN_addsd

NN_andnpd = _ida_allins.NN_andnpd

NN_andpd = _ida_allins.NN_andpd

NN_clflush = _ida_allins.NN_clflush

NN_cmppd = _ida_allins.NN_cmppd

NN_cmpsd = _ida_allins.NN_cmpsd

NN_comisd = _ida_allins.NN_comisd

NN_cvtdq2pd = _ida_allins.NN_cvtdq2pd

NN_cvtdq2ps = _ida_allins.NN_cvtdq2ps

NN_cvtpd2dq = _ida_allins.NN_cvtpd2dq

NN_cvtpd2pi = _ida_allins.NN_cvtpd2pi

NN_cvtpd2ps = _ida_allins.NN_cvtpd2ps

NN_cvtpi2pd = _ida_allins.NN_cvtpi2pd

NN_cvtps2dq = _ida_allins.NN_cvtps2dq

NN_cvtps2pd = _ida_allins.NN_cvtps2pd

NN_cvtsd2si = _ida_allins.NN_cvtsd2si

NN_cvtsd2ss = _ida_allins.NN_cvtsd2ss

NN_cvtsi2sd = _ida_allins.NN_cvtsi2sd

NN_cvtss2sd = _ida_allins.NN_cvtss2sd

NN_cvttpd2dq = _ida_allins.NN_cvttpd2dq

NN_cvttpd2pi = _ida_allins.NN_cvttpd2pi

NN_cvttps2dq = _ida_allins.NN_cvttps2dq

NN_cvttsd2si = _ida_allins.NN_cvttsd2si

NN_divpd = _ida_allins.NN_divpd

NN_divsd = _ida_allins.NN_divsd

NN_lfence = _ida_allins.NN_lfence

NN_maskmovdqu = _ida_allins.NN_maskmovdqu

NN_maxpd = _ida_allins.NN_maxpd

NN_maxsd = _ida_allins.NN_maxsd

NN_mfence = _ida_allins.NN_mfence

NN_minpd = _ida_allins.NN_minpd

NN_minsd = _ida_allins.NN_minsd

NN_movapd = _ida_allins.NN_movapd

NN_movdq2q = _ida_allins.NN_movdq2q

NN_movdqa = _ida_allins.NN_movdqa

NN_movdqu = _ida_allins.NN_movdqu

NN_movhpd = _ida_allins.NN_movhpd

NN_movlpd = _ida_allins.NN_movlpd

NN_movmskpd = _ida_allins.NN_movmskpd

NN_movntdq = _ida_allins.NN_movntdq

NN_movnti = _ida_allins.NN_movnti

NN_movntpd = _ida_allins.NN_movntpd

NN_movq2dq = _ida_allins.NN_movq2dq

NN_movsd = _ida_allins.NN_movsd

NN_movupd = _ida_allins.NN_movupd

NN_mulpd = _ida_allins.NN_mulpd

NN_mulsd = _ida_allins.NN_mulsd

NN_orpd = _ida_allins.NN_orpd

NN_paddq = _ida_allins.NN_paddq

NN_pause = _ida_allins.NN_pause

NN_pmuludq = _ida_allins.NN_pmuludq

NN_pshufd = _ida_allins.NN_pshufd

NN_pshufhw = _ida_allins.NN_pshufhw

NN_pshuflw = _ida_allins.NN_pshuflw

NN_pslldq = _ida_allins.NN_pslldq

NN_psrldq = _ida_allins.NN_psrldq

NN_psubq = _ida_allins.NN_psubq

NN_punpckhqdq = _ida_allins.NN_punpckhqdq

NN_punpcklqdq = _ida_allins.NN_punpcklqdq

NN_shufpd = _ida_allins.NN_shufpd

NN_sqrtpd = _ida_allins.NN_sqrtpd

NN_sqrtsd = _ida_allins.NN_sqrtsd

NN_subpd = _ida_allins.NN_subpd

NN_subsd = _ida_allins.NN_subsd

NN_ucomisd = _ida_allins.NN_ucomisd

NN_unpckhpd = _ida_allins.NN_unpckhpd

NN_unpcklpd = _ida_allins.NN_unpcklpd

NN_xorpd = _ida_allins.NN_xorpd

NN_syscall = _ida_allins.NN_syscall

NN_sysret = _ida_allins.NN_sysret

NN_swapgs = _ida_allins.NN_swapgs

NN_movddup = _ida_allins.NN_movddup

NN_movshdup = _ida_allins.NN_movshdup

NN_movsldup = _ida_allins.NN_movsldup

NN_movsxd = _ida_allins.NN_movsxd

NN_cmpxchg16b = _ida_allins.NN_cmpxchg16b

NN_addsubpd = _ida_allins.NN_addsubpd

NN_addsubps = _ida_allins.NN_addsubps

NN_haddpd = _ida_allins.NN_haddpd

NN_haddps = _ida_allins.NN_haddps

NN_hsubpd = _ida_allins.NN_hsubpd

NN_hsubps = _ida_allins.NN_hsubps

NN_monitor = _ida_allins.NN_monitor

NN_mwait = _ida_allins.NN_mwait

NN_fisttp = _ida_allins.NN_fisttp

NN_lddqu = _ida_allins.NN_lddqu

NN_psignb = _ida_allins.NN_psignb

NN_psignw = _ida_allins.NN_psignw

NN_psignd = _ida_allins.NN_psignd

NN_pshufb = _ida_allins.NN_pshufb

NN_pmulhrsw = _ida_allins.NN_pmulhrsw

NN_pmaddubsw = _ida_allins.NN_pmaddubsw

NN_phsubsw = _ida_allins.NN_phsubsw

NN_phaddsw = _ida_allins.NN_phaddsw

NN_phaddw = _ida_allins.NN_phaddw

NN_phaddd = _ida_allins.NN_phaddd

NN_phsubw = _ida_allins.NN_phsubw

NN_phsubd = _ida_allins.NN_phsubd

NN_palignr = _ida_allins.NN_palignr

NN_pabsb = _ida_allins.NN_pabsb

NN_pabsw = _ida_allins.NN_pabsw

NN_pabsd = _ida_allins.NN_pabsd

NN_vmcall = _ida_allins.NN_vmcall

NN_vmclear = _ida_allins.NN_vmclear

NN_vmlaunch = _ida_allins.NN_vmlaunch

NN_vmresume = _ida_allins.NN_vmresume

NN_vmptrld = _ida_allins.NN_vmptrld

NN_vmptrst = _ida_allins.NN_vmptrst

NN_vmread = _ida_allins.NN_vmread

NN_vmwrite = _ida_allins.NN_vmwrite

NN_vmxoff = _ida_allins.NN_vmxoff

NN_vmxon = _ida_allins.NN_vmxon

NN_ud2 = _ida_allins.NN_ud2

NN_rdtscp = _ida_allins.NN_rdtscp

NN_pfrcpv = _ida_allins.NN_pfrcpv

NN_pfrsqrtv = _ida_allins.NN_pfrsqrtv

NN_cmpeqpd = _ida_allins.NN_cmpeqpd

NN_cmpltpd = _ida_allins.NN_cmpltpd

NN_cmplepd = _ida_allins.NN_cmplepd

NN_cmpunordpd = _ida_allins.NN_cmpunordpd

NN_cmpneqpd = _ida_allins.NN_cmpneqpd

NN_cmpnltpd = _ida_allins.NN_cmpnltpd

NN_cmpnlepd = _ida_allins.NN_cmpnlepd

NN_cmpordpd = _ida_allins.NN_cmpordpd

NN_cmpeqsd = _ida_allins.NN_cmpeqsd

NN_cmpltsd = _ida_allins.NN_cmpltsd

NN_cmplesd = _ida_allins.NN_cmplesd

NN_cmpunordsd = _ida_allins.NN_cmpunordsd

NN_cmpneqsd = _ida_allins.NN_cmpneqsd

NN_cmpnltsd = _ida_allins.NN_cmpnltsd

NN_cmpnlesd = _ida_allins.NN_cmpnlesd

NN_cmpordsd = _ida_allins.NN_cmpordsd

NN_blendpd = _ida_allins.NN_blendpd

NN_blendps = _ida_allins.NN_blendps

NN_blendvpd = _ida_allins.NN_blendvpd

NN_blendvps = _ida_allins.NN_blendvps

NN_dppd = _ida_allins.NN_dppd

NN_dpps = _ida_allins.NN_dpps

NN_extractps = _ida_allins.NN_extractps

NN_insertps = _ida_allins.NN_insertps

NN_movntdqa = _ida_allins.NN_movntdqa

NN_mpsadbw = _ida_allins.NN_mpsadbw

NN_packusdw = _ida_allins.NN_packusdw

NN_pblendvb = _ida_allins.NN_pblendvb

NN_pblendw = _ida_allins.NN_pblendw

NN_pcmpeqq = _ida_allins.NN_pcmpeqq

NN_pextrb = _ida_allins.NN_pextrb

NN_pextrd = _ida_allins.NN_pextrd

NN_pextrq = _ida_allins.NN_pextrq

NN_phminposuw = _ida_allins.NN_phminposuw

NN_pinsrb = _ida_allins.NN_pinsrb

NN_pinsrd = _ida_allins.NN_pinsrd

NN_pinsrq = _ida_allins.NN_pinsrq

NN_pmaxsb = _ida_allins.NN_pmaxsb

NN_pmaxsd = _ida_allins.NN_pmaxsd

NN_pmaxud = _ida_allins.NN_pmaxud

NN_pmaxuw = _ida_allins.NN_pmaxuw

NN_pminsb = _ida_allins.NN_pminsb

NN_pminsd = _ida_allins.NN_pminsd

NN_pminud = _ida_allins.NN_pminud

NN_pminuw = _ida_allins.NN_pminuw

NN_pmovsxbw = _ida_allins.NN_pmovsxbw

NN_pmovsxbd = _ida_allins.NN_pmovsxbd

NN_pmovsxbq = _ida_allins.NN_pmovsxbq

NN_pmovsxwd = _ida_allins.NN_pmovsxwd

NN_pmovsxwq = _ida_allins.NN_pmovsxwq

NN_pmovsxdq = _ida_allins.NN_pmovsxdq

NN_pmovzxbw = _ida_allins.NN_pmovzxbw

NN_pmovzxbd = _ida_allins.NN_pmovzxbd

NN_pmovzxbq = _ida_allins.NN_pmovzxbq

NN_pmovzxwd = _ida_allins.NN_pmovzxwd

NN_pmovzxwq = _ida_allins.NN_pmovzxwq

NN_pmovzxdq = _ida_allins.NN_pmovzxdq

NN_pmuldq = _ida_allins.NN_pmuldq

NN_pmulld = _ida_allins.NN_pmulld

NN_ptest = _ida_allins.NN_ptest

NN_roundpd = _ida_allins.NN_roundpd

NN_roundps = _ida_allins.NN_roundps

NN_roundsd = _ida_allins.NN_roundsd

NN_roundss = _ida_allins.NN_roundss

NN_crc32 = _ida_allins.NN_crc32

NN_pcmpestri = _ida_allins.NN_pcmpestri

NN_pcmpestrm = _ida_allins.NN_pcmpestrm

NN_pcmpistri = _ida_allins.NN_pcmpistri

NN_pcmpistrm = _ida_allins.NN_pcmpistrm

NN_pcmpgtq = _ida_allins.NN_pcmpgtq

NN_popcnt = _ida_allins.NN_popcnt

NN_extrq = _ida_allins.NN_extrq

NN_insertq = _ida_allins.NN_insertq

NN_movntsd = _ida_allins.NN_movntsd

NN_movntss = _ida_allins.NN_movntss

NN_lzcnt = _ida_allins.NN_lzcnt

NN_xgetbv = _ida_allins.NN_xgetbv

NN_xrstor = _ida_allins.NN_xrstor

NN_xsave = _ida_allins.NN_xsave

NN_xsetbv = _ida_allins.NN_xsetbv

NN_getsec = _ida_allins.NN_getsec

NN_clgi = _ida_allins.NN_clgi

NN_invlpga = _ida_allins.NN_invlpga

NN_skinit = _ida_allins.NN_skinit

NN_stgi = _ida_allins.NN_stgi

NN_vmexit = _ida_allins.NN_vmexit

NN_vmload = _ida_allins.NN_vmload

NN_vmmcall = _ida_allins.NN_vmmcall

NN_vmrun = _ida_allins.NN_vmrun

NN_vmsave = _ida_allins.NN_vmsave

NN_invept = _ida_allins.NN_invept

NN_invvpid = _ida_allins.NN_invvpid

NN_movbe = _ida_allins.NN_movbe

NN_aesenc = _ida_allins.NN_aesenc

NN_aesenclast = _ida_allins.NN_aesenclast

NN_aesdec = _ida_allins.NN_aesdec

NN_aesdeclast = _ida_allins.NN_aesdeclast

NN_aesimc = _ida_allins.NN_aesimc

NN_aeskeygenassist = _ida_allins.NN_aeskeygenassist

NN_pclmulqdq = _ida_allins.NN_pclmulqdq

NN_retnw = _ida_allins.NN_retnw

NN_retnd = _ida_allins.NN_retnd

NN_retnq = _ida_allins.NN_retnq

NN_retfw = _ida_allins.NN_retfw

NN_retfd = _ida_allins.NN_retfd

NN_retfq = _ida_allins.NN_retfq

NN_rdrand = _ida_allins.NN_rdrand

NN_adcx = _ida_allins.NN_adcx

NN_adox = _ida_allins.NN_adox

NN_andn = _ida_allins.NN_andn

NN_bextr = _ida_allins.NN_bextr

NN_blsi = _ida_allins.NN_blsi

NN_blsmsk = _ida_allins.NN_blsmsk

NN_blsr = _ida_allins.NN_blsr

NN_bzhi = _ida_allins.NN_bzhi

NN_clac = _ida_allins.NN_clac

NN_mulx = _ida_allins.NN_mulx

NN_pdep = _ida_allins.NN_pdep

NN_pext = _ida_allins.NN_pext

NN_rorx = _ida_allins.NN_rorx

NN_sarx = _ida_allins.NN_sarx

NN_shlx = _ida_allins.NN_shlx

NN_shrx = _ida_allins.NN_shrx

NN_stac = _ida_allins.NN_stac

NN_tzcnt = _ida_allins.NN_tzcnt

NN_xsaveopt = _ida_allins.NN_xsaveopt

NN_invpcid = _ida_allins.NN_invpcid

NN_rdseed = _ida_allins.NN_rdseed

NN_rdfsbase = _ida_allins.NN_rdfsbase

NN_rdgsbase = _ida_allins.NN_rdgsbase

NN_wrfsbase = _ida_allins.NN_wrfsbase

NN_wrgsbase = _ida_allins.NN_wrgsbase

NN_vaddpd = _ida_allins.NN_vaddpd

NN_vaddps = _ida_allins.NN_vaddps

NN_vaddsd = _ida_allins.NN_vaddsd

NN_vaddss = _ida_allins.NN_vaddss

NN_vaddsubpd = _ida_allins.NN_vaddsubpd

NN_vaddsubps = _ida_allins.NN_vaddsubps

NN_vaesdec = _ida_allins.NN_vaesdec

NN_vaesdeclast = _ida_allins.NN_vaesdeclast

NN_vaesenc = _ida_allins.NN_vaesenc

NN_vaesenclast = _ida_allins.NN_vaesenclast

NN_vaesimc = _ida_allins.NN_vaesimc

NN_vaeskeygenassist = _ida_allins.NN_vaeskeygenassist

NN_vandnpd = _ida_allins.NN_vandnpd

NN_vandnps = _ida_allins.NN_vandnps

NN_vandpd = _ida_allins.NN_vandpd

NN_vandps = _ida_allins.NN_vandps

NN_vblendpd = _ida_allins.NN_vblendpd

NN_vblendps = _ida_allins.NN_vblendps

NN_vblendvpd = _ida_allins.NN_vblendvpd

NN_vblendvps = _ida_allins.NN_vblendvps

NN_vbroadcastf128 = _ida_allins.NN_vbroadcastf128

NN_vbroadcasti128 = _ida_allins.NN_vbroadcasti128

NN_vbroadcastsd = _ida_allins.NN_vbroadcastsd

NN_vbroadcastss = _ida_allins.NN_vbroadcastss

NN_vcmppd = _ida_allins.NN_vcmppd

NN_vcmpps = _ida_allins.NN_vcmpps

NN_vcmpsd = _ida_allins.NN_vcmpsd

NN_vcmpss = _ida_allins.NN_vcmpss

NN_vcomisd = _ida_allins.NN_vcomisd

NN_vcomiss = _ida_allins.NN_vcomiss

NN_vcvtdq2pd = _ida_allins.NN_vcvtdq2pd

NN_vcvtdq2ps = _ida_allins.NN_vcvtdq2ps

NN_vcvtpd2dq = _ida_allins.NN_vcvtpd2dq

NN_vcvtpd2ps = _ida_allins.NN_vcvtpd2ps

NN_vcvtph2ps = _ida_allins.NN_vcvtph2ps

NN_vcvtps2dq = _ida_allins.NN_vcvtps2dq

NN_vcvtps2pd = _ida_allins.NN_vcvtps2pd

NN_vcvtps2ph = _ida_allins.NN_vcvtps2ph

NN_vcvtsd2si = _ida_allins.NN_vcvtsd2si

NN_vcvtsd2ss = _ida_allins.NN_vcvtsd2ss

NN_vcvtsi2sd = _ida_allins.NN_vcvtsi2sd

NN_vcvtsi2ss = _ida_allins.NN_vcvtsi2ss

NN_vcvtss2sd = _ida_allins.NN_vcvtss2sd

NN_vcvtss2si = _ida_allins.NN_vcvtss2si

NN_vcvttpd2dq = _ida_allins.NN_vcvttpd2dq

NN_vcvttps2dq = _ida_allins.NN_vcvttps2dq

NN_vcvttsd2si = _ida_allins.NN_vcvttsd2si

NN_vcvttss2si = _ida_allins.NN_vcvttss2si

NN_vdivpd = _ida_allins.NN_vdivpd

NN_vdivps = _ida_allins.NN_vdivps

NN_vdivsd = _ida_allins.NN_vdivsd

NN_vdivss = _ida_allins.NN_vdivss

NN_vdppd = _ida_allins.NN_vdppd

NN_vdpps = _ida_allins.NN_vdpps

NN_vextractf128 = _ida_allins.NN_vextractf128

NN_vextracti128 = _ida_allins.NN_vextracti128

NN_vextractps = _ida_allins.NN_vextractps

NN_vfmadd132pd = _ida_allins.NN_vfmadd132pd

NN_vfmadd132ps = _ida_allins.NN_vfmadd132ps

NN_vfmadd132sd = _ida_allins.NN_vfmadd132sd

NN_vfmadd132ss = _ida_allins.NN_vfmadd132ss

NN_vfmadd213pd = _ida_allins.NN_vfmadd213pd

NN_vfmadd213ps = _ida_allins.NN_vfmadd213ps

NN_vfmadd213sd = _ida_allins.NN_vfmadd213sd

NN_vfmadd213ss = _ida_allins.NN_vfmadd213ss

NN_vfmadd231pd = _ida_allins.NN_vfmadd231pd

NN_vfmadd231ps = _ida_allins.NN_vfmadd231ps

NN_vfmadd231sd = _ida_allins.NN_vfmadd231sd

NN_vfmadd231ss = _ida_allins.NN_vfmadd231ss

NN_vfmaddsub132pd = _ida_allins.NN_vfmaddsub132pd

NN_vfmaddsub132ps = _ida_allins.NN_vfmaddsub132ps

NN_vfmaddsub213pd = _ida_allins.NN_vfmaddsub213pd

NN_vfmaddsub213ps = _ida_allins.NN_vfmaddsub213ps

NN_vfmaddsub231pd = _ida_allins.NN_vfmaddsub231pd

NN_vfmaddsub231ps = _ida_allins.NN_vfmaddsub231ps

NN_vfmsub132pd = _ida_allins.NN_vfmsub132pd

NN_vfmsub132ps = _ida_allins.NN_vfmsub132ps

NN_vfmsub132sd = _ida_allins.NN_vfmsub132sd

NN_vfmsub132ss = _ida_allins.NN_vfmsub132ss

NN_vfmsub213pd = _ida_allins.NN_vfmsub213pd

NN_vfmsub213ps = _ida_allins.NN_vfmsub213ps

NN_vfmsub213sd = _ida_allins.NN_vfmsub213sd

NN_vfmsub213ss = _ida_allins.NN_vfmsub213ss

NN_vfmsub231pd = _ida_allins.NN_vfmsub231pd

NN_vfmsub231ps = _ida_allins.NN_vfmsub231ps

NN_vfmsub231sd = _ida_allins.NN_vfmsub231sd

NN_vfmsub231ss = _ida_allins.NN_vfmsub231ss

NN_vfmsubadd132pd = _ida_allins.NN_vfmsubadd132pd

NN_vfmsubadd132ps = _ida_allins.NN_vfmsubadd132ps

NN_vfmsubadd213pd = _ida_allins.NN_vfmsubadd213pd

NN_vfmsubadd213ps = _ida_allins.NN_vfmsubadd213ps

NN_vfmsubadd231pd = _ida_allins.NN_vfmsubadd231pd

NN_vfmsubadd231ps = _ida_allins.NN_vfmsubadd231ps

NN_vfnmadd132pd = _ida_allins.NN_vfnmadd132pd

NN_vfnmadd132ps = _ida_allins.NN_vfnmadd132ps

NN_vfnmadd132sd = _ida_allins.NN_vfnmadd132sd

NN_vfnmadd132ss = _ida_allins.NN_vfnmadd132ss

NN_vfnmadd213pd = _ida_allins.NN_vfnmadd213pd

NN_vfnmadd213ps = _ida_allins.NN_vfnmadd213ps

NN_vfnmadd213sd = _ida_allins.NN_vfnmadd213sd

NN_vfnmadd213ss = _ida_allins.NN_vfnmadd213ss

NN_vfnmadd231pd = _ida_allins.NN_vfnmadd231pd

NN_vfnmadd231ps = _ida_allins.NN_vfnmadd231ps

NN_vfnmadd231sd = _ida_allins.NN_vfnmadd231sd

NN_vfnmadd231ss = _ida_allins.NN_vfnmadd231ss

NN_vfnmsub132pd = _ida_allins.NN_vfnmsub132pd

NN_vfnmsub132ps = _ida_allins.NN_vfnmsub132ps

NN_vfnmsub132sd = _ida_allins.NN_vfnmsub132sd

NN_vfnmsub132ss = _ida_allins.NN_vfnmsub132ss

NN_vfnmsub213pd = _ida_allins.NN_vfnmsub213pd

NN_vfnmsub213ps = _ida_allins.NN_vfnmsub213ps

NN_vfnmsub213sd = _ida_allins.NN_vfnmsub213sd

NN_vfnmsub213ss = _ida_allins.NN_vfnmsub213ss

NN_vfnmsub231pd = _ida_allins.NN_vfnmsub231pd

NN_vfnmsub231ps = _ida_allins.NN_vfnmsub231ps

NN_vfnmsub231sd = _ida_allins.NN_vfnmsub231sd

NN_vfnmsub231ss = _ida_allins.NN_vfnmsub231ss

NN_vgatherdps = _ida_allins.NN_vgatherdps

NN_vgatherdpd = _ida_allins.NN_vgatherdpd

NN_vgatherqps = _ida_allins.NN_vgatherqps

NN_vgatherqpd = _ida_allins.NN_vgatherqpd

NN_vhaddpd = _ida_allins.NN_vhaddpd

NN_vhaddps = _ida_allins.NN_vhaddps

NN_vhsubpd = _ida_allins.NN_vhsubpd

NN_vhsubps = _ida_allins.NN_vhsubps

NN_vinsertf128 = _ida_allins.NN_vinsertf128

NN_vinserti128 = _ida_allins.NN_vinserti128

NN_vinsertps = _ida_allins.NN_vinsertps

NN_vlddqu = _ida_allins.NN_vlddqu

NN_vldmxcsr = _ida_allins.NN_vldmxcsr

NN_vmaskmovdqu = _ida_allins.NN_vmaskmovdqu

NN_vmaskmovpd = _ida_allins.NN_vmaskmovpd

NN_vmaskmovps = _ida_allins.NN_vmaskmovps

NN_vmaxpd = _ida_allins.NN_vmaxpd

NN_vmaxps = _ida_allins.NN_vmaxps

NN_vmaxsd = _ida_allins.NN_vmaxsd

NN_vmaxss = _ida_allins.NN_vmaxss

NN_vminpd = _ida_allins.NN_vminpd

NN_vminps = _ida_allins.NN_vminps

NN_vminsd = _ida_allins.NN_vminsd

NN_vminss = _ida_allins.NN_vminss

NN_vmovapd = _ida_allins.NN_vmovapd

NN_vmovaps = _ida_allins.NN_vmovaps

NN_vmovd = _ida_allins.NN_vmovd

NN_vmovddup = _ida_allins.NN_vmovddup

NN_vmovdqa = _ida_allins.NN_vmovdqa

NN_vmovdqu = _ida_allins.NN_vmovdqu

NN_vmovhlps = _ida_allins.NN_vmovhlps

NN_vmovhpd = _ida_allins.NN_vmovhpd

NN_vmovhps = _ida_allins.NN_vmovhps

NN_vmovlhps = _ida_allins.NN_vmovlhps

NN_vmovlpd = _ida_allins.NN_vmovlpd

NN_vmovlps = _ida_allins.NN_vmovlps

NN_vmovmskpd = _ida_allins.NN_vmovmskpd

NN_vmovmskps = _ida_allins.NN_vmovmskps

NN_vmovntdq = _ida_allins.NN_vmovntdq

NN_vmovntdqa = _ida_allins.NN_vmovntdqa

NN_vmovntpd = _ida_allins.NN_vmovntpd

NN_vmovntps = _ida_allins.NN_vmovntps

NN_vmovq = _ida_allins.NN_vmovq

NN_vmovsd = _ida_allins.NN_vmovsd

NN_vmovshdup = _ida_allins.NN_vmovshdup

NN_vmovsldup = _ida_allins.NN_vmovsldup

NN_vmovss = _ida_allins.NN_vmovss

NN_vmovupd = _ida_allins.NN_vmovupd

NN_vmovups = _ida_allins.NN_vmovups

NN_vmpsadbw = _ida_allins.NN_vmpsadbw

NN_vmulpd = _ida_allins.NN_vmulpd

NN_vmulps = _ida_allins.NN_vmulps

NN_vmulsd = _ida_allins.NN_vmulsd

NN_vmulss = _ida_allins.NN_vmulss

NN_vorpd = _ida_allins.NN_vorpd

NN_vorps = _ida_allins.NN_vorps

NN_vpabsb = _ida_allins.NN_vpabsb

NN_vpabsd = _ida_allins.NN_vpabsd

NN_vpabsw = _ida_allins.NN_vpabsw

NN_vpackssdw = _ida_allins.NN_vpackssdw

NN_vpacksswb = _ida_allins.NN_vpacksswb

NN_vpackusdw = _ida_allins.NN_vpackusdw

NN_vpackuswb = _ida_allins.NN_vpackuswb

NN_vpaddb = _ida_allins.NN_vpaddb

NN_vpaddd = _ida_allins.NN_vpaddd

NN_vpaddq = _ida_allins.NN_vpaddq

NN_vpaddsb = _ida_allins.NN_vpaddsb

NN_vpaddsw = _ida_allins.NN_vpaddsw

NN_vpaddusb = _ida_allins.NN_vpaddusb

NN_vpaddusw = _ida_allins.NN_vpaddusw

NN_vpaddw = _ida_allins.NN_vpaddw

NN_vpalignr = _ida_allins.NN_vpalignr

NN_vpand = _ida_allins.NN_vpand

NN_vpandn = _ida_allins.NN_vpandn

NN_vpavgb = _ida_allins.NN_vpavgb

NN_vpavgw = _ida_allins.NN_vpavgw

NN_vpblendd = _ida_allins.NN_vpblendd

NN_vpblendvb = _ida_allins.NN_vpblendvb

NN_vpblendw = _ida_allins.NN_vpblendw

NN_vpbroadcastb = _ida_allins.NN_vpbroadcastb

NN_vpbroadcastd = _ida_allins.NN_vpbroadcastd

NN_vpbroadcastq = _ida_allins.NN_vpbroadcastq

NN_vpbroadcastw = _ida_allins.NN_vpbroadcastw

NN_vpclmulqdq = _ida_allins.NN_vpclmulqdq

NN_vpcmpeqb = _ida_allins.NN_vpcmpeqb

NN_vpcmpeqd = _ida_allins.NN_vpcmpeqd

NN_vpcmpeqq = _ida_allins.NN_vpcmpeqq

NN_vpcmpeqw = _ida_allins.NN_vpcmpeqw

NN_vpcmpestri = _ida_allins.NN_vpcmpestri

NN_vpcmpestrm = _ida_allins.NN_vpcmpestrm

NN_vpcmpgtb = _ida_allins.NN_vpcmpgtb

NN_vpcmpgtd = _ida_allins.NN_vpcmpgtd

NN_vpcmpgtq = _ida_allins.NN_vpcmpgtq

NN_vpcmpgtw = _ida_allins.NN_vpcmpgtw

NN_vpcmpistri = _ida_allins.NN_vpcmpistri

NN_vpcmpistrm = _ida_allins.NN_vpcmpistrm

NN_vperm2f128 = _ida_allins.NN_vperm2f128

NN_vperm2i128 = _ida_allins.NN_vperm2i128

NN_vpermd = _ida_allins.NN_vpermd

NN_vpermilpd = _ida_allins.NN_vpermilpd

NN_vpermilps = _ida_allins.NN_vpermilps

NN_vpermpd = _ida_allins.NN_vpermpd

NN_vpermps = _ida_allins.NN_vpermps

NN_vpermq = _ida_allins.NN_vpermq

NN_vpextrb = _ida_allins.NN_vpextrb

NN_vpextrd = _ida_allins.NN_vpextrd

NN_vpextrq = _ida_allins.NN_vpextrq

NN_vpextrw = _ida_allins.NN_vpextrw

NN_vpgatherdd = _ida_allins.NN_vpgatherdd

NN_vpgatherdq = _ida_allins.NN_vpgatherdq

NN_vpgatherqd = _ida_allins.NN_vpgatherqd

NN_vpgatherqq = _ida_allins.NN_vpgatherqq

NN_vphaddd = _ida_allins.NN_vphaddd

NN_vphaddsw = _ida_allins.NN_vphaddsw

NN_vphaddw = _ida_allins.NN_vphaddw

NN_vphminposuw = _ida_allins.NN_vphminposuw

NN_vphsubd = _ida_allins.NN_vphsubd

NN_vphsubsw = _ida_allins.NN_vphsubsw

NN_vphsubw = _ida_allins.NN_vphsubw

NN_vpinsrb = _ida_allins.NN_vpinsrb

NN_vpinsrd = _ida_allins.NN_vpinsrd

NN_vpinsrq = _ida_allins.NN_vpinsrq

NN_vpinsrw = _ida_allins.NN_vpinsrw

NN_vpmaddubsw = _ida_allins.NN_vpmaddubsw

NN_vpmaddwd = _ida_allins.NN_vpmaddwd

NN_vpmaskmovd = _ida_allins.NN_vpmaskmovd

NN_vpmaskmovq = _ida_allins.NN_vpmaskmovq

NN_vpmaxsb = _ida_allins.NN_vpmaxsb

NN_vpmaxsd = _ida_allins.NN_vpmaxsd

NN_vpmaxsw = _ida_allins.NN_vpmaxsw

NN_vpmaxub = _ida_allins.NN_vpmaxub

NN_vpmaxud = _ida_allins.NN_vpmaxud

NN_vpmaxuw = _ida_allins.NN_vpmaxuw

NN_vpminsb = _ida_allins.NN_vpminsb

NN_vpminsd = _ida_allins.NN_vpminsd

NN_vpminsw = _ida_allins.NN_vpminsw

NN_vpminub = _ida_allins.NN_vpminub

NN_vpminud = _ida_allins.NN_vpminud

NN_vpminuw = _ida_allins.NN_vpminuw

NN_vpmovmskb = _ida_allins.NN_vpmovmskb

NN_vpmovsxbd = _ida_allins.NN_vpmovsxbd

NN_vpmovsxbq = _ida_allins.NN_vpmovsxbq

NN_vpmovsxbw = _ida_allins.NN_vpmovsxbw

NN_vpmovsxdq = _ida_allins.NN_vpmovsxdq

NN_vpmovsxwd = _ida_allins.NN_vpmovsxwd

NN_vpmovsxwq = _ida_allins.NN_vpmovsxwq

NN_vpmovzxbd = _ida_allins.NN_vpmovzxbd

NN_vpmovzxbq = _ida_allins.NN_vpmovzxbq

NN_vpmovzxbw = _ida_allins.NN_vpmovzxbw

NN_vpmovzxdq = _ida_allins.NN_vpmovzxdq

NN_vpmovzxwd = _ida_allins.NN_vpmovzxwd

NN_vpmovzxwq = _ida_allins.NN_vpmovzxwq

NN_vpmuldq = _ida_allins.NN_vpmuldq

NN_vpmulhrsw = _ida_allins.NN_vpmulhrsw

NN_vpmulhuw = _ida_allins.NN_vpmulhuw

NN_vpmulhw = _ida_allins.NN_vpmulhw

NN_vpmulld = _ida_allins.NN_vpmulld

NN_vpmullw = _ida_allins.NN_vpmullw

NN_vpmuludq = _ida_allins.NN_vpmuludq

NN_vpor = _ida_allins.NN_vpor

NN_vpsadbw = _ida_allins.NN_vpsadbw

NN_vpshufb = _ida_allins.NN_vpshufb

NN_vpshufd = _ida_allins.NN_vpshufd

NN_vpshufhw = _ida_allins.NN_vpshufhw

NN_vpshuflw = _ida_allins.NN_vpshuflw

NN_vpsignb = _ida_allins.NN_vpsignb

NN_vpsignd = _ida_allins.NN_vpsignd

NN_vpsignw = _ida_allins.NN_vpsignw

NN_vpslld = _ida_allins.NN_vpslld

NN_vpslldq = _ida_allins.NN_vpslldq

NN_vpsllq = _ida_allins.NN_vpsllq

NN_vpsllvd = _ida_allins.NN_vpsllvd

NN_vpsllvq = _ida_allins.NN_vpsllvq

NN_vpsllw = _ida_allins.NN_vpsllw

NN_vpsrad = _ida_allins.NN_vpsrad

NN_vpsravd = _ida_allins.NN_vpsravd

NN_vpsraw = _ida_allins.NN_vpsraw

NN_vpsrld = _ida_allins.NN_vpsrld

NN_vpsrldq = _ida_allins.NN_vpsrldq

NN_vpsrlq = _ida_allins.NN_vpsrlq

NN_vpsrlvd = _ida_allins.NN_vpsrlvd

NN_vpsrlvq = _ida_allins.NN_vpsrlvq

NN_vpsrlw = _ida_allins.NN_vpsrlw

NN_vpsubb = _ida_allins.NN_vpsubb

NN_vpsubd = _ida_allins.NN_vpsubd

NN_vpsubq = _ida_allins.NN_vpsubq

NN_vpsubsb = _ida_allins.NN_vpsubsb

NN_vpsubsw = _ida_allins.NN_vpsubsw

NN_vpsubusb = _ida_allins.NN_vpsubusb

NN_vpsubusw = _ida_allins.NN_vpsubusw

NN_vpsubw = _ida_allins.NN_vpsubw

NN_vptest = _ida_allins.NN_vptest

NN_vpunpckhbw = _ida_allins.NN_vpunpckhbw

NN_vpunpckhdq = _ida_allins.NN_vpunpckhdq

NN_vpunpckhqdq = _ida_allins.NN_vpunpckhqdq

NN_vpunpckhwd = _ida_allins.NN_vpunpckhwd

NN_vpunpcklbw = _ida_allins.NN_vpunpcklbw

NN_vpunpckldq = _ida_allins.NN_vpunpckldq

NN_vpunpcklqdq = _ida_allins.NN_vpunpcklqdq

NN_vpunpcklwd = _ida_allins.NN_vpunpcklwd

NN_vpxor = _ida_allins.NN_vpxor

NN_vrcpps = _ida_allins.NN_vrcpps

NN_vrcpss = _ida_allins.NN_vrcpss

NN_vroundpd = _ida_allins.NN_vroundpd

NN_vroundps = _ida_allins.NN_vroundps

NN_vroundsd = _ida_allins.NN_vroundsd

NN_vroundss = _ida_allins.NN_vroundss

NN_vrsqrtps = _ida_allins.NN_vrsqrtps

NN_vrsqrtss = _ida_allins.NN_vrsqrtss

NN_vshufpd = _ida_allins.NN_vshufpd

NN_vshufps = _ida_allins.NN_vshufps

NN_vsqrtpd = _ida_allins.NN_vsqrtpd

NN_vsqrtps = _ida_allins.NN_vsqrtps

NN_vsqrtsd = _ida_allins.NN_vsqrtsd

NN_vsqrtss = _ida_allins.NN_vsqrtss

NN_vstmxcsr = _ida_allins.NN_vstmxcsr

NN_vsubpd = _ida_allins.NN_vsubpd

NN_vsubps = _ida_allins.NN_vsubps

NN_vsubsd = _ida_allins.NN_vsubsd

NN_vsubss = _ida_allins.NN_vsubss

NN_vtestpd = _ida_allins.NN_vtestpd

NN_vtestps = _ida_allins.NN_vtestps

NN_vucomisd = _ida_allins.NN_vucomisd

NN_vucomiss = _ida_allins.NN_vucomiss

NN_vunpckhpd = _ida_allins.NN_vunpckhpd

NN_vunpckhps = _ida_allins.NN_vunpckhps

NN_vunpcklpd = _ida_allins.NN_vunpcklpd

NN_vunpcklps = _ida_allins.NN_vunpcklps

NN_vxorpd = _ida_allins.NN_vxorpd

NN_vxorps = _ida_allins.NN_vxorps

NN_vzeroall = _ida_allins.NN_vzeroall

NN_vzeroupper = _ida_allins.NN_vzeroupper

NN_xabort = _ida_allins.NN_xabort

NN_xbegin = _ida_allins.NN_xbegin

NN_xend = _ida_allins.NN_xend

NN_xtest = _ida_allins.NN_xtest

NN_vmgetinfo = _ida_allins.NN_vmgetinfo

NN_vmsetinfo = _ida_allins.NN_vmsetinfo

NN_vmdxdsbl = _ida_allins.NN_vmdxdsbl

NN_vmdxenbl = _ida_allins.NN_vmdxenbl

NN_vmcpuid = _ida_allins.NN_vmcpuid

NN_vmhlt = _ida_allins.NN_vmhlt

NN_vmsplaf = _ida_allins.NN_vmsplaf

NN_vmpushfd = _ida_allins.NN_vmpushfd

NN_vmpopfd = _ida_allins.NN_vmpopfd

NN_vmcli = _ida_allins.NN_vmcli

NN_vmsti = _ida_allins.NN_vmsti

NN_vmiretd = _ida_allins.NN_vmiretd

NN_vmsgdt = _ida_allins.NN_vmsgdt

NN_vmsidt = _ida_allins.NN_vmsidt

NN_vmsldt = _ida_allins.NN_vmsldt

NN_vmstr = _ida_allins.NN_vmstr

NN_vmsdte = _ida_allins.NN_vmsdte

NN_vpcext = _ida_allins.NN_vpcext

NN_vfmaddsubps = _ida_allins.NN_vfmaddsubps

NN_vfmaddsubpd = _ida_allins.NN_vfmaddsubpd

NN_vfmsubaddps = _ida_allins.NN_vfmsubaddps

NN_vfmsubaddpd = _ida_allins.NN_vfmsubaddpd

NN_vfmaddps = _ida_allins.NN_vfmaddps

NN_vfmaddpd = _ida_allins.NN_vfmaddpd

NN_vfmaddss = _ida_allins.NN_vfmaddss

NN_vfmaddsd = _ida_allins.NN_vfmaddsd

NN_vfmsubps = _ida_allins.NN_vfmsubps

NN_vfmsubpd = _ida_allins.NN_vfmsubpd

NN_vfmsubss = _ida_allins.NN_vfmsubss

NN_vfmsubsd = _ida_allins.NN_vfmsubsd

NN_vfnmaddps = _ida_allins.NN_vfnmaddps

NN_vfnmaddpd = _ida_allins.NN_vfnmaddpd

NN_vfnmaddss = _ida_allins.NN_vfnmaddss

NN_vfnmaddsd = _ida_allins.NN_vfnmaddsd

NN_vfnmsubps = _ida_allins.NN_vfnmsubps

NN_vfnmsubpd = _ida_allins.NN_vfnmsubpd

NN_vfnmsubss = _ida_allins.NN_vfnmsubss

NN_vfnmsubsd = _ida_allins.NN_vfnmsubsd

NN_bndmk = _ida_allins.NN_bndmk

NN_bndcl = _ida_allins.NN_bndcl

NN_bndcu = _ida_allins.NN_bndcu

NN_bndcn = _ida_allins.NN_bndcn

NN_bndmov = _ida_allins.NN_bndmov

NN_bndldx = _ida_allins.NN_bndldx

NN_bndstx = _ida_allins.NN_bndstx

NN_xrstors = _ida_allins.NN_xrstors

NN_xsavec = _ida_allins.NN_xsavec

NN_xsaves = _ida_allins.NN_xsaves

NN_prefetchwt1 = _ida_allins.NN_prefetchwt1

NN_clflushopt = _ida_allins.NN_clflushopt

NN_clwb = _ida_allins.NN_clwb

NN_pcommit = _ida_allins.NN_pcommit

NN_rdpkru = _ida_allins.NN_rdpkru

NN_wrpkru = _ida_allins.NN_wrpkru

NN_vcmpeqpd = _ida_allins.NN_vcmpeqpd

NN_vcmpltpd = _ida_allins.NN_vcmpltpd

NN_vcmplepd = _ida_allins.NN_vcmplepd

NN_vcmpunordpd = _ida_allins.NN_vcmpunordpd

NN_vcmpneqpd = _ida_allins.NN_vcmpneqpd

NN_vcmpnltpd = _ida_allins.NN_vcmpnltpd

NN_vcmpnlepd = _ida_allins.NN_vcmpnlepd

NN_vcmpordpd = _ida_allins.NN_vcmpordpd

NN_vcmpeq_uqpd = _ida_allins.NN_vcmpeq_uqpd

NN_vcmpngepd = _ida_allins.NN_vcmpngepd

NN_vcmpngtpd = _ida_allins.NN_vcmpngtpd

NN_vcmpfalsepd = _ida_allins.NN_vcmpfalsepd

NN_vcmpneq_oqpd = _ida_allins.NN_vcmpneq_oqpd

NN_vcmpgepd = _ida_allins.NN_vcmpgepd

NN_vcmpgtpd = _ida_allins.NN_vcmpgtpd

NN_vcmptruepd = _ida_allins.NN_vcmptruepd

NN_vcmpeq_ospd = _ida_allins.NN_vcmpeq_ospd

NN_vcmplt_oqpd = _ida_allins.NN_vcmplt_oqpd

NN_vcmple_oqpd = _ida_allins.NN_vcmple_oqpd

NN_vcmpunord_spd = _ida_allins.NN_vcmpunord_spd

NN_vcmpneq_uspd = _ida_allins.NN_vcmpneq_uspd

NN_vcmpnlt_uqpd = _ida_allins.NN_vcmpnlt_uqpd

NN_vcmpnle_uqpd = _ida_allins.NN_vcmpnle_uqpd

NN_vcmpord_spd = _ida_allins.NN_vcmpord_spd

NN_vcmpeq_uspd = _ida_allins.NN_vcmpeq_uspd

NN_vcmpnge_uqpd = _ida_allins.NN_vcmpnge_uqpd

NN_vcmpngt_uqpd = _ida_allins.NN_vcmpngt_uqpd

NN_vcmpfalse_ospd = _ida_allins.NN_vcmpfalse_ospd

NN_vcmpneq_ospd = _ida_allins.NN_vcmpneq_ospd

NN_vcmpge_oqpd = _ida_allins.NN_vcmpge_oqpd

NN_vcmpgt_oqpd = _ida_allins.NN_vcmpgt_oqpd

NN_vcmptrue_uspd = _ida_allins.NN_vcmptrue_uspd

NN_vcmpeqps = _ida_allins.NN_vcmpeqps

NN_vcmpltps = _ida_allins.NN_vcmpltps

NN_vcmpleps = _ida_allins.NN_vcmpleps

NN_vcmpunordps = _ida_allins.NN_vcmpunordps

NN_vcmpneqps = _ida_allins.NN_vcmpneqps

NN_vcmpnltps = _ida_allins.NN_vcmpnltps

NN_vcmpnleps = _ida_allins.NN_vcmpnleps

NN_vcmpordps = _ida_allins.NN_vcmpordps

NN_vcmpeq_uqps = _ida_allins.NN_vcmpeq_uqps

NN_vcmpngeps = _ida_allins.NN_vcmpngeps

NN_vcmpngtps = _ida_allins.NN_vcmpngtps

NN_vcmpfalseps = _ida_allins.NN_vcmpfalseps

NN_vcmpneq_oqps = _ida_allins.NN_vcmpneq_oqps

NN_vcmpgeps = _ida_allins.NN_vcmpgeps

NN_vcmpgtps = _ida_allins.NN_vcmpgtps

NN_vcmptrueps = _ida_allins.NN_vcmptrueps

NN_vcmpeq_osps = _ida_allins.NN_vcmpeq_osps

NN_vcmplt_oqps = _ida_allins.NN_vcmplt_oqps

NN_vcmple_oqps = _ida_allins.NN_vcmple_oqps

NN_vcmpunord_sps = _ida_allins.NN_vcmpunord_sps

NN_vcmpneq_usps = _ida_allins.NN_vcmpneq_usps

NN_vcmpnlt_uqps = _ida_allins.NN_vcmpnlt_uqps

NN_vcmpnle_uqps = _ida_allins.NN_vcmpnle_uqps

NN_vcmpord_sps = _ida_allins.NN_vcmpord_sps

NN_vcmpeq_usps = _ida_allins.NN_vcmpeq_usps

NN_vcmpnge_uqps = _ida_allins.NN_vcmpnge_uqps

NN_vcmpngt_uqps = _ida_allins.NN_vcmpngt_uqps

NN_vcmpfalse_osps = _ida_allins.NN_vcmpfalse_osps

NN_vcmpneq_osps = _ida_allins.NN_vcmpneq_osps

NN_vcmpge_oqps = _ida_allins.NN_vcmpge_oqps

NN_vcmpgt_oqps = _ida_allins.NN_vcmpgt_oqps

NN_vcmptrue_usps = _ida_allins.NN_vcmptrue_usps

NN_vcmpeqsd = _ida_allins.NN_vcmpeqsd

NN_vcmpltsd = _ida_allins.NN_vcmpltsd

NN_vcmplesd = _ida_allins.NN_vcmplesd

NN_vcmpunordsd = _ida_allins.NN_vcmpunordsd

NN_vcmpneqsd = _ida_allins.NN_vcmpneqsd

NN_vcmpnltsd = _ida_allins.NN_vcmpnltsd

NN_vcmpnlesd = _ida_allins.NN_vcmpnlesd

NN_vcmpordsd = _ida_allins.NN_vcmpordsd

NN_vcmpeq_uqsd = _ida_allins.NN_vcmpeq_uqsd

NN_vcmpngesd = _ida_allins.NN_vcmpngesd

NN_vcmpngtsd = _ida_allins.NN_vcmpngtsd

NN_vcmpfalsesd = _ida_allins.NN_vcmpfalsesd

NN_vcmpneq_oqsd = _ida_allins.NN_vcmpneq_oqsd

NN_vcmpgesd = _ida_allins.NN_vcmpgesd

NN_vcmpgtsd = _ida_allins.NN_vcmpgtsd

NN_vcmptruesd = _ida_allins.NN_vcmptruesd

NN_vcmpeq_ossd = _ida_allins.NN_vcmpeq_ossd

NN_vcmplt_oqsd = _ida_allins.NN_vcmplt_oqsd

NN_vcmple_oqsd = _ida_allins.NN_vcmple_oqsd

NN_vcmpunord_ssd = _ida_allins.NN_vcmpunord_ssd

NN_vcmpneq_ussd = _ida_allins.NN_vcmpneq_ussd

NN_vcmpnlt_uqsd = _ida_allins.NN_vcmpnlt_uqsd

NN_vcmpnle_uqsd = _ida_allins.NN_vcmpnle_uqsd

NN_vcmpord_ssd = _ida_allins.NN_vcmpord_ssd

NN_vcmpeq_ussd = _ida_allins.NN_vcmpeq_ussd

NN_vcmpnge_uqsd = _ida_allins.NN_vcmpnge_uqsd

NN_vcmpngt_uqsd = _ida_allins.NN_vcmpngt_uqsd

NN_vcmpfalse_ossd = _ida_allins.NN_vcmpfalse_ossd

NN_vcmpneq_ossd = _ida_allins.NN_vcmpneq_ossd

NN_vcmpge_oqsd = _ida_allins.NN_vcmpge_oqsd

NN_vcmpgt_oqsd = _ida_allins.NN_vcmpgt_oqsd

NN_vcmptrue_ussd = _ida_allins.NN_vcmptrue_ussd

NN_vcmpeqss = _ida_allins.NN_vcmpeqss

NN_vcmpltss = _ida_allins.NN_vcmpltss

NN_vcmpless = _ida_allins.NN_vcmpless

NN_vcmpunordss = _ida_allins.NN_vcmpunordss

NN_vcmpneqss = _ida_allins.NN_vcmpneqss

NN_vcmpnltss = _ida_allins.NN_vcmpnltss

NN_vcmpnless = _ida_allins.NN_vcmpnless

NN_vcmpordss = _ida_allins.NN_vcmpordss

NN_vcmpeq_uqss = _ida_allins.NN_vcmpeq_uqss

NN_vcmpngess = _ida_allins.NN_vcmpngess

NN_vcmpngtss = _ida_allins.NN_vcmpngtss

NN_vcmpfalsess = _ida_allins.NN_vcmpfalsess

NN_vcmpneq_oqss = _ida_allins.NN_vcmpneq_oqss

NN_vcmpgess = _ida_allins.NN_vcmpgess

NN_vcmpgtss = _ida_allins.NN_vcmpgtss

NN_vcmptruess = _ida_allins.NN_vcmptruess

NN_vcmpeq_osss = _ida_allins.NN_vcmpeq_osss

NN_vcmplt_oqss = _ida_allins.NN_vcmplt_oqss

NN_vcmple_oqss = _ida_allins.NN_vcmple_oqss

NN_vcmpunord_sss = _ida_allins.NN_vcmpunord_sss

NN_vcmpneq_usss = _ida_allins.NN_vcmpneq_usss

NN_vcmpnlt_uqss = _ida_allins.NN_vcmpnlt_uqss

NN_vcmpnle_uqss = _ida_allins.NN_vcmpnle_uqss

NN_vcmpord_sss = _ida_allins.NN_vcmpord_sss

NN_vcmpeq_usss = _ida_allins.NN_vcmpeq_usss

NN_vcmpnge_uqss = _ida_allins.NN_vcmpnge_uqss

NN_vcmpngt_uqss = _ida_allins.NN_vcmpngt_uqss

NN_vcmpfalse_osss = _ida_allins.NN_vcmpfalse_osss

NN_vcmpneq_osss = _ida_allins.NN_vcmpneq_osss

NN_vcmpge_oqss = _ida_allins.NN_vcmpge_oqss

NN_vcmpgt_oqss = _ida_allins.NN_vcmpgt_oqss

NN_vcmptrue_usss = _ida_allins.NN_vcmptrue_usss

NN_valignd = _ida_allins.NN_valignd

NN_valignq = _ida_allins.NN_valignq

NN_vblendmpd = _ida_allins.NN_vblendmpd

NN_vblendmps = _ida_allins.NN_vblendmps

NN_vpblendmb = _ida_allins.NN_vpblendmb

NN_vpblendmw = _ida_allins.NN_vpblendmw

NN_vpblendmd = _ida_allins.NN_vpblendmd

NN_vpblendmq = _ida_allins.NN_vpblendmq

NN_vbroadcastf32x2 = _ida_allins.NN_vbroadcastf32x2

NN_vbroadcastf32x4 = _ida_allins.NN_vbroadcastf32x4

NN_vbroadcastf64x2 = _ida_allins.NN_vbroadcastf64x2

NN_vbroadcastf32x8 = _ida_allins.NN_vbroadcastf32x8

NN_vbroadcastf64x4 = _ida_allins.NN_vbroadcastf64x4

NN_vbroadcasti32x2 = _ida_allins.NN_vbroadcasti32x2

NN_vbroadcasti32x4 = _ida_allins.NN_vbroadcasti32x4

NN_vbroadcasti64x2 = _ida_allins.NN_vbroadcasti64x2

NN_vbroadcasti32x8 = _ida_allins.NN_vbroadcasti32x8

NN_vbroadcasti64x4 = _ida_allins.NN_vbroadcasti64x4

NN_vcompresspd = _ida_allins.NN_vcompresspd

NN_vcompressps = _ida_allins.NN_vcompressps

NN_vcvtpd2qq = _ida_allins.NN_vcvtpd2qq

NN_vcvtpd2udq = _ida_allins.NN_vcvtpd2udq

NN_vcvtpd2uqq = _ida_allins.NN_vcvtpd2uqq

NN_vcvtps2udq = _ida_allins.NN_vcvtps2udq

NN_vcvtps2qq = _ida_allins.NN_vcvtps2qq

NN_vcvtps2uqq = _ida_allins.NN_vcvtps2uqq

NN_vcvtqq2pd = _ida_allins.NN_vcvtqq2pd

NN_vcvtqq2ps = _ida_allins.NN_vcvtqq2ps

NN_vcvtsd2usi = _ida_allins.NN_vcvtsd2usi

NN_vcvtss2usi = _ida_allins.NN_vcvtss2usi

NN_vcvttpd2qq = _ida_allins.NN_vcvttpd2qq

NN_vcvttpd2udq = _ida_allins.NN_vcvttpd2udq

NN_vcvttpd2uqq = _ida_allins.NN_vcvttpd2uqq

NN_vcvttps2udq = _ida_allins.NN_vcvttps2udq

NN_vcvttps2qq = _ida_allins.NN_vcvttps2qq

NN_vcvttps2uqq = _ida_allins.NN_vcvttps2uqq

NN_vcvttsd2usi = _ida_allins.NN_vcvttsd2usi

NN_vcvttss2usi = _ida_allins.NN_vcvttss2usi

NN_vcvtudq2pd = _ida_allins.NN_vcvtudq2pd

NN_vcvtudq2ps = _ida_allins.NN_vcvtudq2ps

NN_vcvtuqq2pd = _ida_allins.NN_vcvtuqq2pd

NN_vcvtuqq2ps = _ida_allins.NN_vcvtuqq2ps

NN_vcvtusi2sd = _ida_allins.NN_vcvtusi2sd

NN_vcvtusi2ss = _ida_allins.NN_vcvtusi2ss

NN_vdbpsadbw = _ida_allins.NN_vdbpsadbw

NN_vexpandpd = _ida_allins.NN_vexpandpd

NN_vexpandps = _ida_allins.NN_vexpandps

NN_vextractf32x4 = _ida_allins.NN_vextractf32x4

NN_vextractf64x2 = _ida_allins.NN_vextractf64x2

NN_vextractf32x8 = _ida_allins.NN_vextractf32x8

NN_vextractf64x4 = _ida_allins.NN_vextractf64x4

NN_vextracti32x4 = _ida_allins.NN_vextracti32x4

NN_vextracti64x2 = _ida_allins.NN_vextracti64x2

NN_vextracti32x8 = _ida_allins.NN_vextracti32x8

NN_vextracti64x4 = _ida_allins.NN_vextracti64x4

NN_vfixupimmpd = _ida_allins.NN_vfixupimmpd

NN_vfixupimmps = _ida_allins.NN_vfixupimmps

NN_vfixupimmsd = _ida_allins.NN_vfixupimmsd

NN_vfixupimmss = _ida_allins.NN_vfixupimmss

NN_vfpclasspd = _ida_allins.NN_vfpclasspd

NN_vfpclassps = _ida_allins.NN_vfpclassps

NN_vfpclasssd = _ida_allins.NN_vfpclasssd

NN_vfpclassss = _ida_allins.NN_vfpclassss

NN_vgetexppd = _ida_allins.NN_vgetexppd

NN_vgetexpps = _ida_allins.NN_vgetexpps

NN_vgetexpsd = _ida_allins.NN_vgetexpsd

NN_vgetexpss = _ida_allins.NN_vgetexpss

NN_vgetmantpd = _ida_allins.NN_vgetmantpd

NN_vgetmantps = _ida_allins.NN_vgetmantps

NN_vgetmantsd = _ida_allins.NN_vgetmantsd

NN_vgetmantss = _ida_allins.NN_vgetmantss

NN_vinsertf32x4 = _ida_allins.NN_vinsertf32x4

NN_vinsertf64x2 = _ida_allins.NN_vinsertf64x2

NN_vinsertf32x8 = _ida_allins.NN_vinsertf32x8

NN_vinsertf64x4 = _ida_allins.NN_vinsertf64x4

NN_vinserti32x4 = _ida_allins.NN_vinserti32x4

NN_vinserti64x2 = _ida_allins.NN_vinserti64x2

NN_vinserti32x8 = _ida_allins.NN_vinserti32x8

NN_vinserti64x4 = _ida_allins.NN_vinserti64x4

NN_vmovdqa32 = _ida_allins.NN_vmovdqa32

NN_vmovdqa64 = _ida_allins.NN_vmovdqa64

NN_vmovdqu8 = _ida_allins.NN_vmovdqu8

NN_vmovdqu16 = _ida_allins.NN_vmovdqu16

NN_vmovdqu32 = _ida_allins.NN_vmovdqu32

NN_vmovdqu64 = _ida_allins.NN_vmovdqu64

NN_vpabsq = _ida_allins.NN_vpabsq

NN_vpandd = _ida_allins.NN_vpandd

NN_vpandq = _ida_allins.NN_vpandq

NN_vpandnd = _ida_allins.NN_vpandnd

NN_vpandnq = _ida_allins.NN_vpandnq

NN_vpbroadcastmb2q = _ida_allins.NN_vpbroadcastmb2q

NN_vpbroadcastmw2d = _ida_allins.NN_vpbroadcastmw2d

NN_vpcmpb = _ida_allins.NN_vpcmpb

NN_vpcmpub = _ida_allins.NN_vpcmpub

NN_vpcmpd = _ida_allins.NN_vpcmpd

NN_vpcmpud = _ida_allins.NN_vpcmpud

NN_vpcmpq = _ida_allins.NN_vpcmpq

NN_vpcmpuq = _ida_allins.NN_vpcmpuq

NN_vpcmpw = _ida_allins.NN_vpcmpw

NN_vpcmpuw = _ida_allins.NN_vpcmpuw

NN_vpcompressd = _ida_allins.NN_vpcompressd

NN_vpcompressq = _ida_allins.NN_vpcompressq

NN_vpconflictd = _ida_allins.NN_vpconflictd

NN_vpconflictq = _ida_allins.NN_vpconflictq

NN_vpermb = _ida_allins.NN_vpermb

NN_vpermw = _ida_allins.NN_vpermw

NN_vpermi2b = _ida_allins.NN_vpermi2b

NN_vpermi2w = _ida_allins.NN_vpermi2w

NN_vpermi2d = _ida_allins.NN_vpermi2d

NN_vpermi2q = _ida_allins.NN_vpermi2q

NN_vpermi2ps = _ida_allins.NN_vpermi2ps

NN_vpermi2pd = _ida_allins.NN_vpermi2pd

NN_vpermt2b = _ida_allins.NN_vpermt2b

NN_vpermt2w = _ida_allins.NN_vpermt2w

NN_vpermt2d = _ida_allins.NN_vpermt2d

NN_vpermt2q = _ida_allins.NN_vpermt2q

NN_vpermt2ps = _ida_allins.NN_vpermt2ps

NN_vpermt2pd = _ida_allins.NN_vpermt2pd

NN_vpexpandd = _ida_allins.NN_vpexpandd

NN_vpexpandq = _ida_allins.NN_vpexpandq

NN_vplzcntd = _ida_allins.NN_vplzcntd

NN_vplzcntq = _ida_allins.NN_vplzcntq

NN_vpmadd52luq = _ida_allins.NN_vpmadd52luq

NN_vpmadd52huq = _ida_allins.NN_vpmadd52huq

NN_vpmaxsq = _ida_allins.NN_vpmaxsq

NN_vpmaxuq = _ida_allins.NN_vpmaxuq

NN_vpminsq = _ida_allins.NN_vpminsq

NN_vpminuq = _ida_allins.NN_vpminuq

NN_vpmovm2b = _ida_allins.NN_vpmovm2b

NN_vpmovm2w = _ida_allins.NN_vpmovm2w

NN_vpmovm2d = _ida_allins.NN_vpmovm2d

NN_vpmovm2q = _ida_allins.NN_vpmovm2q

NN_vpmovb2m = _ida_allins.NN_vpmovb2m

NN_vpmovw2m = _ida_allins.NN_vpmovw2m

NN_vpmovd2m = _ida_allins.NN_vpmovd2m

NN_vpmovq2m = _ida_allins.NN_vpmovq2m

NN_vpmovqb = _ida_allins.NN_vpmovqb

NN_vpmovsqb = _ida_allins.NN_vpmovsqb

NN_vpmovusqb = _ida_allins.NN_vpmovusqb

NN_vpmovqw = _ida_allins.NN_vpmovqw

NN_vpmovsqw = _ida_allins.NN_vpmovsqw

NN_vpmovusqw = _ida_allins.NN_vpmovusqw

NN_vpmovqd = _ida_allins.NN_vpmovqd

NN_vpmovsqd = _ida_allins.NN_vpmovsqd

NN_vpmovusqd = _ida_allins.NN_vpmovusqd

NN_vpmovdb = _ida_allins.NN_vpmovdb

NN_vpmovsdb = _ida_allins.NN_vpmovsdb

NN_vpmovusdb = _ida_allins.NN_vpmovusdb

NN_vpmovdw = _ida_allins.NN_vpmovdw

NN_vpmovsdw = _ida_allins.NN_vpmovsdw

NN_vpmovusdw = _ida_allins.NN_vpmovusdw

NN_vpmovwb = _ida_allins.NN_vpmovwb

NN_vpmovswb = _ida_allins.NN_vpmovswb

NN_vpmovuswb = _ida_allins.NN_vpmovuswb

NN_vpmullq = _ida_allins.NN_vpmullq

NN_vpmultishiftqb = _ida_allins.NN_vpmultishiftqb

NN_vpord = _ida_allins.NN_vpord

NN_vporq = _ida_allins.NN_vporq

NN_vprold = _ida_allins.NN_vprold

NN_vprolvd = _ida_allins.NN_vprolvd

NN_vprolq = _ida_allins.NN_vprolq

NN_vprolvq = _ida_allins.NN_vprolvq

NN_vprord = _ida_allins.NN_vprord

NN_vprorvd = _ida_allins.NN_vprorvd

NN_vprorq = _ida_allins.NN_vprorq

NN_vprorvq = _ida_allins.NN_vprorvq

NN_vpscatterdd = _ida_allins.NN_vpscatterdd

NN_vpscatterdq = _ida_allins.NN_vpscatterdq

NN_vpscatterqd = _ida_allins.NN_vpscatterqd

NN_vpscatterqq = _ida_allins.NN_vpscatterqq

NN_vpsraq = _ida_allins.NN_vpsraq

NN_vpsllvw = _ida_allins.NN_vpsllvw

NN_vpsrlvw = _ida_allins.NN_vpsrlvw

NN_vptestnmb = _ida_allins.NN_vptestnmb

NN_vptestnmw = _ida_allins.NN_vptestnmw

NN_vptestnmd = _ida_allins.NN_vptestnmd

NN_vptestnmq = _ida_allins.NN_vptestnmq

NN_vshuff32x4 = _ida_allins.NN_vshuff32x4

NN_vshuff64x2 = _ida_allins.NN_vshuff64x2

NN_vshufi32x4 = _ida_allins.NN_vshufi32x4

NN_vshufi64x2 = _ida_allins.NN_vshufi64x2

NN_vpternlogd = _ida_allins.NN_vpternlogd

NN_vpternlogq = _ida_allins.NN_vpternlogq

NN_vptestmb = _ida_allins.NN_vptestmb

NN_vptestmw = _ida_allins.NN_vptestmw

NN_vptestmd = _ida_allins.NN_vptestmd

NN_vptestmq = _ida_allins.NN_vptestmq

NN_vpsravw = _ida_allins.NN_vpsravw

NN_vpsravq = _ida_allins.NN_vpsravq

NN_vpxord = _ida_allins.NN_vpxord

NN_vpxorq = _ida_allins.NN_vpxorq

NN_vrangepd = _ida_allins.NN_vrangepd

NN_vrangeps = _ida_allins.NN_vrangeps

NN_vrangesd = _ida_allins.NN_vrangesd

NN_vrangess = _ida_allins.NN_vrangess

NN_vrcp14pd = _ida_allins.NN_vrcp14pd

NN_vrcp14sd = _ida_allins.NN_vrcp14sd

NN_vrcp14ps = _ida_allins.NN_vrcp14ps

NN_vrcp14ss = _ida_allins.NN_vrcp14ss

NN_vreducepd = _ida_allins.NN_vreducepd

NN_vreducesd = _ida_allins.NN_vreducesd

NN_vreduceps = _ida_allins.NN_vreduceps

NN_vreducess = _ida_allins.NN_vreducess

NN_vrndscalepd = _ida_allins.NN_vrndscalepd

NN_vrndscalesd = _ida_allins.NN_vrndscalesd

NN_vrndscaleps = _ida_allins.NN_vrndscaleps

NN_vrndscaless = _ida_allins.NN_vrndscaless

NN_vrsqrt14pd = _ida_allins.NN_vrsqrt14pd

NN_vrsqrt14sd = _ida_allins.NN_vrsqrt14sd

NN_vrsqrt14ps = _ida_allins.NN_vrsqrt14ps

NN_vrsqrt14ss = _ida_allins.NN_vrsqrt14ss

NN_vscalefpd = _ida_allins.NN_vscalefpd

NN_vscalefsd = _ida_allins.NN_vscalefsd

NN_vscalefps = _ida_allins.NN_vscalefps

NN_vscalefss = _ida_allins.NN_vscalefss

NN_vscatterdps = _ida_allins.NN_vscatterdps

NN_vscatterdpd = _ida_allins.NN_vscatterdpd

NN_vscatterqps = _ida_allins.NN_vscatterqps

NN_vscatterqpd = _ida_allins.NN_vscatterqpd

NN_vexp2pd = _ida_allins.NN_vexp2pd

NN_vexp2ps = _ida_allins.NN_vexp2ps

NN_vrcp28pd = _ida_allins.NN_vrcp28pd

NN_vrcp28sd = _ida_allins.NN_vrcp28sd

NN_vrcp28ps = _ida_allins.NN_vrcp28ps

NN_vrcp28ss = _ida_allins.NN_vrcp28ss

NN_vrsqrt28pd = _ida_allins.NN_vrsqrt28pd

NN_vrsqrt28sd = _ida_allins.NN_vrsqrt28sd

NN_vrsqrt28ps = _ida_allins.NN_vrsqrt28ps

NN_vrsqrt28ss = _ida_allins.NN_vrsqrt28ss

NN_vgatherpf0dps = _ida_allins.NN_vgatherpf0dps

NN_vgatherpf0qps = _ida_allins.NN_vgatherpf0qps

NN_vgatherpf0dpd = _ida_allins.NN_vgatherpf0dpd

NN_vgatherpf0qpd = _ida_allins.NN_vgatherpf0qpd

NN_vgatherpf1dps = _ida_allins.NN_vgatherpf1dps

NN_vgatherpf1qps = _ida_allins.NN_vgatherpf1qps

NN_vgatherpf1dpd = _ida_allins.NN_vgatherpf1dpd

NN_vgatherpf1qpd = _ida_allins.NN_vgatherpf1qpd

NN_vscatterpf0dps = _ida_allins.NN_vscatterpf0dps

NN_vscatterpf0qps = _ida_allins.NN_vscatterpf0qps

NN_vscatterpf0dpd = _ida_allins.NN_vscatterpf0dpd

NN_vscatterpf0qpd = _ida_allins.NN_vscatterpf0qpd

NN_vscatterpf1dps = _ida_allins.NN_vscatterpf1dps

NN_vscatterpf1qps = _ida_allins.NN_vscatterpf1qps

NN_vscatterpf1dpd = _ida_allins.NN_vscatterpf1dpd

NN_vscatterpf1qpd = _ida_allins.NN_vscatterpf1qpd

NN_vpcmpltd = _ida_allins.NN_vpcmpltd

NN_vpcmpled = _ida_allins.NN_vpcmpled

NN_vpcmpneqd = _ida_allins.NN_vpcmpneqd

NN_vpcmpnltd = _ida_allins.NN_vpcmpnltd

NN_vpcmpnled = _ida_allins.NN_vpcmpnled

NN_vpcmpequd = _ida_allins.NN_vpcmpequd

NN_vpcmpltud = _ida_allins.NN_vpcmpltud

NN_vpcmpleud = _ida_allins.NN_vpcmpleud

NN_vpcmpnequd = _ida_allins.NN_vpcmpnequd

NN_vpcmpnltud = _ida_allins.NN_vpcmpnltud

NN_vpcmpnleud = _ida_allins.NN_vpcmpnleud

NN_vpcmpltq = _ida_allins.NN_vpcmpltq

NN_vpcmpleq = _ida_allins.NN_vpcmpleq

NN_vpcmpneqq = _ida_allins.NN_vpcmpneqq

NN_vpcmpnltq = _ida_allins.NN_vpcmpnltq

NN_vpcmpnleq = _ida_allins.NN_vpcmpnleq

NN_vpcmpequq = _ida_allins.NN_vpcmpequq

NN_vpcmpltuq = _ida_allins.NN_vpcmpltuq

NN_vpcmpleuq = _ida_allins.NN_vpcmpleuq

NN_vpcmpnequq = _ida_allins.NN_vpcmpnequq

NN_vpcmpnltuq = _ida_allins.NN_vpcmpnltuq

NN_vpcmpnleuq = _ida_allins.NN_vpcmpnleuq

NN_kaddw = _ida_allins.NN_kaddw

NN_kaddb = _ida_allins.NN_kaddb

NN_kaddq = _ida_allins.NN_kaddq

NN_kaddd = _ida_allins.NN_kaddd

NN_kandw = _ida_allins.NN_kandw

NN_kandb = _ida_allins.NN_kandb

NN_kandq = _ida_allins.NN_kandq

NN_kandd = _ida_allins.NN_kandd

NN_kandnw = _ida_allins.NN_kandnw

NN_kandnb = _ida_allins.NN_kandnb

NN_kandnq = _ida_allins.NN_kandnq

NN_kandnd = _ida_allins.NN_kandnd

NN_kmovw = _ida_allins.NN_kmovw

NN_kmovb = _ida_allins.NN_kmovb

NN_kmovq = _ida_allins.NN_kmovq

NN_kmovd = _ida_allins.NN_kmovd

NN_kunpckbw = _ida_allins.NN_kunpckbw

NN_kunpckwd = _ida_allins.NN_kunpckwd

NN_kunpckdq = _ida_allins.NN_kunpckdq

NN_knotw = _ida_allins.NN_knotw

NN_knotb = _ida_allins.NN_knotb

NN_knotq = _ida_allins.NN_knotq

NN_knotd = _ida_allins.NN_knotd

NN_korw = _ida_allins.NN_korw

NN_korb = _ida_allins.NN_korb

NN_korq = _ida_allins.NN_korq

NN_kord = _ida_allins.NN_kord

NN_kortestw = _ida_allins.NN_kortestw

NN_kortestb = _ida_allins.NN_kortestb

NN_kortestq = _ida_allins.NN_kortestq

NN_kortestd = _ida_allins.NN_kortestd

NN_kshiftlw = _ida_allins.NN_kshiftlw

NN_kshiftlb = _ida_allins.NN_kshiftlb

NN_kshiftlq = _ida_allins.NN_kshiftlq

NN_kshiftld = _ida_allins.NN_kshiftld

NN_kshiftrw = _ida_allins.NN_kshiftrw

NN_kshiftrb = _ida_allins.NN_kshiftrb

NN_kshiftrq = _ida_allins.NN_kshiftrq

NN_kshiftrd = _ida_allins.NN_kshiftrd

NN_kxnorw = _ida_allins.NN_kxnorw

NN_kxnorb = _ida_allins.NN_kxnorb

NN_kxnorq = _ida_allins.NN_kxnorq

NN_kxnord = _ida_allins.NN_kxnord

NN_ktestw = _ida_allins.NN_ktestw

NN_ktestb = _ida_allins.NN_ktestb

NN_ktestq = _ida_allins.NN_ktestq

NN_ktestd = _ida_allins.NN_ktestd

NN_kxorw = _ida_allins.NN_kxorw

NN_kxorb = _ida_allins.NN_kxorb

NN_kxorq = _ida_allins.NN_kxorq

NN_kxord = _ida_allins.NN_kxord

NN_sha1rnds4 = _ida_allins.NN_sha1rnds4

NN_sha1nexte = _ida_allins.NN_sha1nexte

NN_sha1msg1 = _ida_allins.NN_sha1msg1

NN_sha1msg2 = _ida_allins.NN_sha1msg2

NN_sha256rnds2 = _ida_allins.NN_sha256rnds2

NN_sha256msg1 = _ida_allins.NN_sha256msg1

NN_sha256msg2 = _ida_allins.NN_sha256msg2

NN_encls = _ida_allins.NN_encls

NN_enclu = _ida_allins.NN_enclu

NN_vfrczpd = _ida_allins.NN_vfrczpd

NN_vfrczps = _ida_allins.NN_vfrczps

NN_vfrczsd = _ida_allins.NN_vfrczsd

NN_vfrczss = _ida_allins.NN_vfrczss

NN_vpcmov = _ida_allins.NN_vpcmov

NN_vpcomb = _ida_allins.NN_vpcomb

NN_vpcomd = _ida_allins.NN_vpcomd

NN_vpcomq = _ida_allins.NN_vpcomq

NN_vpcomub = _ida_allins.NN_vpcomub

NN_vpcomud = _ida_allins.NN_vpcomud

NN_vpcomuq = _ida_allins.NN_vpcomuq

NN_vpcomuw = _ida_allins.NN_vpcomuw

NN_vpcomw = _ida_allins.NN_vpcomw

NN_vpermil2pd = _ida_allins.NN_vpermil2pd

NN_vpermil2ps = _ida_allins.NN_vpermil2ps

NN_vphaddbd = _ida_allins.NN_vphaddbd

NN_vphaddbq = _ida_allins.NN_vphaddbq

NN_vphaddbw = _ida_allins.NN_vphaddbw

NN_vphadddq = _ida_allins.NN_vphadddq

NN_vphaddubd = _ida_allins.NN_vphaddubd

NN_vphaddubq = _ida_allins.NN_vphaddubq

NN_vphaddubw = _ida_allins.NN_vphaddubw

NN_vphaddudq = _ida_allins.NN_vphaddudq

NN_vphadduwd = _ida_allins.NN_vphadduwd

NN_vphadduwq = _ida_allins.NN_vphadduwq

NN_vphaddwd = _ida_allins.NN_vphaddwd

NN_vphaddwq = _ida_allins.NN_vphaddwq

NN_vphsubbw = _ida_allins.NN_vphsubbw

NN_vphsubdq = _ida_allins.NN_vphsubdq

NN_vphsubwd = _ida_allins.NN_vphsubwd

NN_vpmacsdd = _ida_allins.NN_vpmacsdd

NN_vpmacsdqh = _ida_allins.NN_vpmacsdqh

NN_vpmacsdql = _ida_allins.NN_vpmacsdql

NN_vpmacssdd = _ida_allins.NN_vpmacssdd

NN_vpmacssdqh = _ida_allins.NN_vpmacssdqh

NN_vpmacssdql = _ida_allins.NN_vpmacssdql

NN_vpmacsswd = _ida_allins.NN_vpmacsswd

NN_vpmacssww = _ida_allins.NN_vpmacssww

NN_vpmacswd = _ida_allins.NN_vpmacswd

NN_vpmacsww = _ida_allins.NN_vpmacsww

NN_vpmadcsswd = _ida_allins.NN_vpmadcsswd

NN_vpmadcswd = _ida_allins.NN_vpmadcswd

NN_vpperm = _ida_allins.NN_vpperm

NN_vprotb = _ida_allins.NN_vprotb

NN_vprotd = _ida_allins.NN_vprotd

NN_vprotq = _ida_allins.NN_vprotq

NN_vprotw = _ida_allins.NN_vprotw

NN_vpshab = _ida_allins.NN_vpshab

NN_vpshad = _ida_allins.NN_vpshad

NN_vpshaq = _ida_allins.NN_vpshaq

NN_vpshaw = _ida_allins.NN_vpshaw

NN_vpshlb = _ida_allins.NN_vpshlb

NN_vpshld = _ida_allins.NN_vpshld

NN_vpshlq = _ida_allins.NN_vpshlq

NN_vpshlw = _ida_allins.NN_vpshlw

NN_vpcomltb = _ida_allins.NN_vpcomltb

NN_vpcomleb = _ida_allins.NN_vpcomleb

NN_vpcomgtb = _ida_allins.NN_vpcomgtb

NN_vpcomgeb = _ida_allins.NN_vpcomgeb

NN_vpcomeqb = _ida_allins.NN_vpcomeqb

NN_vpcomneqb = _ida_allins.NN_vpcomneqb

NN_vpcomfalseb = _ida_allins.NN_vpcomfalseb

NN_vpcomtrueb = _ida_allins.NN_vpcomtrueb

NN_vpcomltw = _ida_allins.NN_vpcomltw

NN_vpcomlew = _ida_allins.NN_vpcomlew

NN_vpcomgtw = _ida_allins.NN_vpcomgtw

NN_vpcomgew = _ida_allins.NN_vpcomgew

NN_vpcomeqw = _ida_allins.NN_vpcomeqw

NN_vpcomneqw = _ida_allins.NN_vpcomneqw

NN_vpcomfalsew = _ida_allins.NN_vpcomfalsew

NN_vpcomtruew = _ida_allins.NN_vpcomtruew

NN_vpcomltd = _ida_allins.NN_vpcomltd

NN_vpcomled = _ida_allins.NN_vpcomled

NN_vpcomgtd = _ida_allins.NN_vpcomgtd

NN_vpcomged = _ida_allins.NN_vpcomged

NN_vpcomeqd = _ida_allins.NN_vpcomeqd

NN_vpcomneqd = _ida_allins.NN_vpcomneqd

NN_vpcomfalsed = _ida_allins.NN_vpcomfalsed

NN_vpcomtrued = _ida_allins.NN_vpcomtrued

NN_vpcomltq = _ida_allins.NN_vpcomltq

NN_vpcomleq = _ida_allins.NN_vpcomleq

NN_vpcomgtq = _ida_allins.NN_vpcomgtq

NN_vpcomgeq = _ida_allins.NN_vpcomgeq

NN_vpcomeqq = _ida_allins.NN_vpcomeqq

NN_vpcomneqq = _ida_allins.NN_vpcomneqq

NN_vpcomfalseq = _ida_allins.NN_vpcomfalseq

NN_vpcomtrueq = _ida_allins.NN_vpcomtrueq

NN_vpcomltub = _ida_allins.NN_vpcomltub

NN_vpcomleub = _ida_allins.NN_vpcomleub

NN_vpcomgtub = _ida_allins.NN_vpcomgtub

NN_vpcomgeub = _ida_allins.NN_vpcomgeub

NN_vpcomequb = _ida_allins.NN_vpcomequb

NN_vpcomnequb = _ida_allins.NN_vpcomnequb

NN_vpcomfalseub = _ida_allins.NN_vpcomfalseub

NN_vpcomtrueub = _ida_allins.NN_vpcomtrueub

NN_vpcomltuw = _ida_allins.NN_vpcomltuw

NN_vpcomleuw = _ida_allins.NN_vpcomleuw

NN_vpcomgtuw = _ida_allins.NN_vpcomgtuw

NN_vpcomgeuw = _ida_allins.NN_vpcomgeuw

NN_vpcomequw = _ida_allins.NN_vpcomequw

NN_vpcomnequw = _ida_allins.NN_vpcomnequw

NN_vpcomfalseuw = _ida_allins.NN_vpcomfalseuw

NN_vpcomtrueuw = _ida_allins.NN_vpcomtrueuw

NN_vpcomltud = _ida_allins.NN_vpcomltud

NN_vpcomleud = _ida_allins.NN_vpcomleud

NN_vpcomgtud = _ida_allins.NN_vpcomgtud

NN_vpcomgeud = _ida_allins.NN_vpcomgeud

NN_vpcomequd = _ida_allins.NN_vpcomequd

NN_vpcomnequd = _ida_allins.NN_vpcomnequd

NN_vpcomfalseud = _ida_allins.NN_vpcomfalseud

NN_vpcomtrueud = _ida_allins.NN_vpcomtrueud

NN_vpcomltuq = _ida_allins.NN_vpcomltuq

NN_vpcomleuq = _ida_allins.NN_vpcomleuq

NN_vpcomgtuq = _ida_allins.NN_vpcomgtuq

NN_vpcomgeuq = _ida_allins.NN_vpcomgeuq

NN_vpcomequq = _ida_allins.NN_vpcomequq

NN_vpcomnequq = _ida_allins.NN_vpcomnequq

NN_vpcomfalseuq = _ida_allins.NN_vpcomfalseuq

NN_vpcomtrueuq = _ida_allins.NN_vpcomtrueuq

NN_monitorx = _ida_allins.NN_monitorx

NN_mwaitx = _ida_allins.NN_mwaitx

NN_clzero = _ida_allins.NN_clzero

NN_ptwrite = _ida_allins.NN_ptwrite

NN_v4fmaddps = _ida_allins.NN_v4fmaddps

NN_v4fnmaddps = _ida_allins.NN_v4fnmaddps

NN_v4fmaddss = _ida_allins.NN_v4fmaddss

NN_v4fnmaddss = _ida_allins.NN_v4fnmaddss

NN_vp4dpwssd = _ida_allins.NN_vp4dpwssd

NN_vp4dpwssds = _ida_allins.NN_vp4dpwssds

NN_vpopcntd = _ida_allins.NN_vpopcntd

NN_vpopcntq = _ida_allins.NN_vpopcntq

NN_rdpid = _ida_allins.NN_rdpid

NN_vmfunc = _ida_allins.NN_vmfunc

NN_incsspd = _ida_allins.NN_incsspd

NN_incsspq = _ida_allins.NN_incsspq

NN_rdsspd = _ida_allins.NN_rdsspd

NN_rdsspq = _ida_allins.NN_rdsspq

NN_saveprevssp = _ida_allins.NN_saveprevssp

NN_rstorssp = _ida_allins.NN_rstorssp

NN_wrssd = _ida_allins.NN_wrssd

NN_wrssq = _ida_allins.NN_wrssq

NN_wrussd = _ida_allins.NN_wrussd

NN_wrussq = _ida_allins.NN_wrussq

NN_setssbsy = _ida_allins.NN_setssbsy

NN_clrssbsy = _ida_allins.NN_clrssbsy

NN_endbr64 = _ida_allins.NN_endbr64

NN_endbr32 = _ida_allins.NN_endbr32

NN_ud0 = _ida_allins.NN_ud0

NN_ud1 = _ida_allins.NN_ud1

NN_enqcmd = _ida_allins.NN_enqcmd

NN_enqcmds = _ida_allins.NN_enqcmds

NN_mcommit = _ida_allins.NN_mcommit

NN_rdpru = _ida_allins.NN_rdpru

NN_cldemote = _ida_allins.NN_cldemote

NN_enclv = _ida_allins.NN_enclv

NN_movdiri = _ida_allins.NN_movdiri

NN_movdir64b = _ida_allins.NN_movdir64b

NN_tpause = _ida_allins.NN_tpause

NN_umonitor = _ida_allins.NN_umonitor

NN_umwait = _ida_allins.NN_umwait

NN_serialize = _ida_allins.NN_serialize

NN_xresldtrk = _ida_allins.NN_xresldtrk

NN_xsusldtrk = _ida_allins.NN_xsusldtrk

NN_gf2p8mulb = _ida_allins.NN_gf2p8mulb

NN_gf2p8affineqb = _ida_allins.NN_gf2p8affineqb

NN_gf2p8affineinvqb = _ida_allins.NN_gf2p8affineinvqb

NN_vgf2p8mulb = _ida_allins.NN_vgf2p8mulb

NN_vgf2p8affineqb = _ida_allins.NN_vgf2p8affineqb

NN_vgf2p8affineinvqb = _ida_allins.NN_vgf2p8affineinvqb

NN_fxsave64 = _ida_allins.NN_fxsave64

NN_fxrstor64 = _ida_allins.NN_fxrstor64

NN_last = _ida_allins.NN_last

I5_null = _ida_allins.I5_null

I5_aci = _ida_allins.I5_aci

I5_adc = _ida_allins.I5_adc

Z80_adc = _ida_allins.Z80_adc

I5_add = _ida_allins.I5_add

Z80_add = _ida_allins.Z80_add

I5_adi = _ida_allins.I5_adi

I5_ana = _ida_allins.I5_ana

I5_ani = _ida_allins.I5_ani

I5_call = _ida_allins.I5_call

I5_cnz = _ida_allins.I5_cnz

I5_cz = _ida_allins.I5_cz

I5_cnc = _ida_allins.I5_cnc

I5_cc = _ida_allins.I5_cc

I5_cpo = _ida_allins.I5_cpo

I5_cpe = _ida_allins.I5_cpe

I5_cp = _ida_allins.I5_cp

I5_cm = _ida_allins.I5_cm

I5_cmc = _ida_allins.I5_cmc

I5_cmp = _ida_allins.I5_cmp

I5_cpi = _ida_allins.I5_cpi

I5_cma = _ida_allins.I5_cma

I5_daa = _ida_allins.I5_daa

I5_dad = _ida_allins.I5_dad

I5_dcr = _ida_allins.I5_dcr

I5_dcx = _ida_allins.I5_dcx

I5_di = _ida_allins.I5_di

Z80_di = _ida_allins.Z80_di

I5_ei = _ida_allins.I5_ei

Z80_ei = _ida_allins.Z80_ei

I5_halt = _ida_allins.I5_halt

I5_in = _ida_allins.I5_in

Z80_in = _ida_allins.Z80_in

I5_inr = _ida_allins.I5_inr

I5_inx = _ida_allins.I5_inx

I5_jmp = _ida_allins.I5_jmp

I5_jnz = _ida_allins.I5_jnz

I5_jz = _ida_allins.I5_jz

I5_jnc = _ida_allins.I5_jnc

I5_jc = _ida_allins.I5_jc

I5_jpo = _ida_allins.I5_jpo

I5_jpe = _ida_allins.I5_jpe

I5_jp = _ida_allins.I5_jp

I5_jm = _ida_allins.I5_jm

I5_lda = _ida_allins.I5_lda

I5_ldax = _ida_allins.I5_ldax

I5_lhld = _ida_allins.I5_lhld

I5_lxi = _ida_allins.I5_lxi

I5_mov = _ida_allins.I5_mov

I5_mvi = _ida_allins.I5_mvi

I5_nop = _ida_allins.I5_nop

I5_ora = _ida_allins.I5_ora

I5_ori = _ida_allins.I5_ori

I5_out = _ida_allins.I5_out

Z80_out = _ida_allins.Z80_out

I5_pchl = _ida_allins.I5_pchl

I5_pop = _ida_allins.I5_pop

Z80_pop = _ida_allins.Z80_pop

I5_push = _ida_allins.I5_push

Z80_push = _ida_allins.Z80_push

I5_ret = _ida_allins.I5_ret

I5_rnz = _ida_allins.I5_rnz

I5_rz = _ida_allins.I5_rz

I5_rnc = _ida_allins.I5_rnc

I5_rc = _ida_allins.I5_rc

I5_rpo = _ida_allins.I5_rpo

I5_rpe = _ida_allins.I5_rpe

I5_rp = _ida_allins.I5_rp

I5_rm = _ida_allins.I5_rm

I5_ral = _ida_allins.I5_ral

I5_rlc = _ida_allins.I5_rlc

I5_rar = _ida_allins.I5_rar

I5_rrc = _ida_allins.I5_rrc

I5_rst = _ida_allins.I5_rst

I5_sbb = _ida_allins.I5_sbb

I5_sbi = _ida_allins.I5_sbi

I5_stc = _ida_allins.I5_stc

I5_sphl = _ida_allins.I5_sphl

I5_sta = _ida_allins.I5_sta

I5_stax = _ida_allins.I5_stax

I5_shld = _ida_allins.I5_shld

I5_sui = _ida_allins.I5_sui

I5_sub = _ida_allins.I5_sub

Z80_sub = _ida_allins.Z80_sub

I5_xra = _ida_allins.I5_xra

I5_xri = _ida_allins.I5_xri

I5_xchg = _ida_allins.I5_xchg

I5_xthl = _ida_allins.I5_xthl

I5_rim = _ida_allins.I5_rim

I5_sim = _ida_allins.I5_sim

Z80_and = _ida_allins.Z80_and

Z80_bit = _ida_allins.Z80_bit

Z80_call = _ida_allins.Z80_call

Z80_ccf = _ida_allins.Z80_ccf

Z80_cp = _ida_allins.Z80_cp

Z80_cpd = _ida_allins.Z80_cpd

Z80_cpdr = _ida_allins.Z80_cpdr

Z80_cpi = _ida_allins.Z80_cpi

Z80_cpir = _ida_allins.Z80_cpir

Z80_cpl = _ida_allins.Z80_cpl

Z80_dec = _ida_allins.Z80_dec

Z80_djnz = _ida_allins.Z80_djnz

Z80_ex = _ida_allins.Z80_ex

Z80_exx = _ida_allins.Z80_exx

Z80_halt = _ida_allins.Z80_halt

Z80_im = _ida_allins.Z80_im

Z80_inc = _ida_allins.Z80_inc

Z80_ind = _ida_allins.Z80_ind

Z80_indr = _ida_allins.Z80_indr

Z80_ini = _ida_allins.Z80_ini

Z80_inir = _ida_allins.Z80_inir

Z80_jp = _ida_allins.Z80_jp

Z80_jr = _ida_allins.Z80_jr

Z80_ld = _ida_allins.Z80_ld

Z80_ldd = _ida_allins.Z80_ldd

Z80_lddr = _ida_allins.Z80_lddr

Z80_ldi = _ida_allins.Z80_ldi

Z80_ldir = _ida_allins.Z80_ldir

Z80_neg = _ida_allins.Z80_neg

Z80_or = _ida_allins.Z80_or

Z80_otdr = _ida_allins.Z80_otdr

Z80_otir = _ida_allins.Z80_otir

Z80_outd = _ida_allins.Z80_outd

Z80_outi = _ida_allins.Z80_outi

Z80_res = _ida_allins.Z80_res

Z80_ret = _ida_allins.Z80_ret

Z80_reti = _ida_allins.Z80_reti

Z80_retn = _ida_allins.Z80_retn

Z80_rl = _ida_allins.Z80_rl

Z80_rla = _ida_allins.Z80_rla

Z80_rlc = _ida_allins.Z80_rlc

Z80_rlca = _ida_allins.Z80_rlca

Z80_rld = _ida_allins.Z80_rld

Z80_rr = _ida_allins.Z80_rr

Z80_rra = _ida_allins.Z80_rra

Z80_rrc = _ida_allins.Z80_rrc

Z80_rrca = _ida_allins.Z80_rrca

Z80_rrd = _ida_allins.Z80_rrd

Z80_scf = _ida_allins.Z80_scf

Z80_sbc = _ida_allins.Z80_sbc

Z80_set = _ida_allins.Z80_set

Z80_sla = _ida_allins.Z80_sla

Z80_sra = _ida_allins.Z80_sra

Z80_srl = _ida_allins.Z80_srl

Z80_xor = _ida_allins.Z80_xor

Z80_inp = _ida_allins.Z80_inp

Z80_outp = _ida_allins.Z80_outp

Z80_srr = _ida_allins.Z80_srr

HD_in0 = _ida_allins.HD_in0

Z80_in0 = _ida_allins.Z80_in0

HD_mlt = _ida_allins.HD_mlt

Z80_mlt = _ida_allins.Z80_mlt

HD_otim = _ida_allins.HD_otim

Z80_otim = _ida_allins.Z80_otim

HD_otimr = _ida_allins.HD_otimr

Z80_otimr = _ida_allins.Z80_otimr

HD_otdm = _ida_allins.HD_otdm

Z80_otdm = _ida_allins.Z80_otdm

HD_otdmr = _ida_allins.HD_otdmr

Z80_otdmr = _ida_allins.Z80_otdmr

HD_out0 = _ida_allins.HD_out0

Z80_out0 = _ida_allins.Z80_out0

HD_slp = _ida_allins.HD_slp

Z80_slp = _ida_allins.Z80_slp

HD_tst = _ida_allins.HD_tst

Z80_tst = _ida_allins.Z80_tst

HD_tstio = _ida_allins.HD_tstio

Z80_tstio = _ida_allins.Z80_tstio

A80_lbcd = _ida_allins.A80_lbcd

A80_lded = _ida_allins.A80_lded

A80_lspd = _ida_allins.A80_lspd

A80_lixd = _ida_allins.A80_lixd

A80_liyd = _ida_allins.A80_liyd

A80_sbcd = _ida_allins.A80_sbcd

A80_sded = _ida_allins.A80_sded

A80_sspd = _ida_allins.A80_sspd

A80_sixd = _ida_allins.A80_sixd

A80_siyd = _ida_allins.A80_siyd

A80_xtix = _ida_allins.A80_xtix

A80_xtiy = _ida_allins.A80_xtiy

A80_spix = _ida_allins.A80_spix

A80_spiy = _ida_allins.A80_spiy

A80_pcix = _ida_allins.A80_pcix

A80_pciy = _ida_allins.A80_pciy

A80_mvra = _ida_allins.A80_mvra

A80_mvia = _ida_allins.A80_mvia

A80_mvar = _ida_allins.A80_mvar

A80_mvai = _ida_allins.A80_mvai

A80_addix = _ida_allins.A80_addix

A80_addiy = _ida_allins.A80_addiy

A80_addc = _ida_allins.A80_addc

A80_addcix = _ida_allins.A80_addcix

A80_addciy = _ida_allins.A80_addciy

A80_subc = _ida_allins.A80_subc

A80_subcix = _ida_allins.A80_subcix

A80_subciy = _ida_allins.A80_subciy

A80_jrc = _ida_allins.A80_jrc

A80_jrnc = _ida_allins.A80_jrnc

A80_jrz = _ida_allins.A80_jrz

A80_jrnz = _ida_allins.A80_jrnz

A80_cmpi = _ida_allins.A80_cmpi

A80_cmpd = _ida_allins.A80_cmpd

A80_im0 = _ida_allins.A80_im0

A80_im1 = _ida_allins.A80_im1

A80_im2 = _ida_allins.A80_im2

A80_otd = _ida_allins.A80_otd

A80_oti = _ida_allins.A80_oti

I5_dsub = _ida_allins.I5_dsub

I5_arhl = _ida_allins.I5_arhl

I5_rdel = _ida_allins.I5_rdel

I5_ldhi = _ida_allins.I5_ldhi

I5_ldsi = _ida_allins.I5_ldsi

I5_shlx = _ida_allins.I5_shlx

I5_lhlx = _ida_allins.I5_lhlx

I5_rstv = _ida_allins.I5_rstv

I5_jx5 = _ida_allins.I5_jx5

I5_jnx5 = _ida_allins.I5_jnx5

Z80_cplw = _ida_allins.Z80_cplw

Z80_swap = _ida_allins.Z80_swap

Z80_inw = _ida_allins.Z80_inw

Z80_outw = _ida_allins.Z80_outw

Z80_ldw = _ida_allins.Z80_ldw

Z80_addw = _ida_allins.Z80_addw

Z80_subw = _ida_allins.Z80_subw

Z80_adcw = _ida_allins.Z80_adcw

Z80_sbcw = _ida_allins.Z80_sbcw

Z80_andw = _ida_allins.Z80_andw

Z80_xorw = _ida_allins.Z80_xorw

Z80_orw = _ida_allins.Z80_orw

Z80_cpw = _ida_allins.Z80_cpw

Z80_ddir = _ida_allins.Z80_ddir

Z80_calr = _ida_allins.Z80_calr

Z80_ldctl = _ida_allins.Z80_ldctl

Z80_mtest = _ida_allins.Z80_mtest

Z80_exxx = _ida_allins.Z80_exxx

Z80_exxy = _ida_allins.Z80_exxy

Z80_exall = _ida_allins.Z80_exall

Z80_setc = _ida_allins.Z80_setc

Z80_resc = _ida_allins.Z80_resc

Z80_rlcw = _ida_allins.Z80_rlcw

Z80_rrcw = _ida_allins.Z80_rrcw

Z80_rlw = _ida_allins.Z80_rlw

Z80_rrw = _ida_allins.Z80_rrw

Z80_slaw = _ida_allins.Z80_slaw

Z80_sraw = _ida_allins.Z80_sraw

Z80_srlw = _ida_allins.Z80_srlw

Z80_multw = _ida_allins.Z80_multw

Z80_multuw = _ida_allins.Z80_multuw

Z80_divuw = _ida_allins.Z80_divuw

Z80_outaw = _ida_allins.Z80_outaw

Z80_inaw = _ida_allins.Z80_inaw

Z80_outa = _ida_allins.Z80_outa

Z80_ina = _ida_allins.Z80_ina

Z80_negw = _ida_allins.Z80_negw

Z80_exts = _ida_allins.Z80_exts

Z80_extsw = _ida_allins.Z80_extsw

Z80_btest = _ida_allins.Z80_btest

Z80_ldiw = _ida_allins.Z80_ldiw

Z80_ldirw = _ida_allins.Z80_ldirw

Z80_lddw = _ida_allins.Z80_lddw

Z80_lddrw = _ida_allins.Z80_lddrw

Z80_iniw = _ida_allins.Z80_iniw

Z80_inirw = _ida_allins.Z80_inirw

Z80_indw = _ida_allins.Z80_indw

Z80_indrw = _ida_allins.Z80_indrw

Z80_outiw = _ida_allins.Z80_outiw

Z80_otirw = _ida_allins.Z80_otirw

Z80_outdw = _ida_allins.Z80_outdw

Z80_otdrw = _ida_allins.Z80_otdrw

GB_ldh = _ida_allins.GB_ldh

GB_stop = _ida_allins.GB_stop

I5_last = _ida_allins.I5_last

I860_null = _ida_allins.I860_null

I860_adds = _ida_allins.I860_adds

I860_addu = _ida_allins.I860_addu

I860_and = _ida_allins.I860_and

I860_andh = _ida_allins.I860_andh

I860_andnot = _ida_allins.I860_andnot

I860_andnoth = _ida_allins.I860_andnoth

I860_bc = _ida_allins.I860_bc

I860_bc_t = _ida_allins.I860_bc_t

I860_bla = _ida_allins.I860_bla

I860_bnc = _ida_allins.I860_bnc

I860_bnc_t = _ida_allins.I860_bnc_t

I860_br = _ida_allins.I860_br

I860_bri = _ida_allins.I860_bri

I860_bte = _ida_allins.I860_bte

I860_btne = _ida_allins.I860_btne

I860_call = _ida_allins.I860_call

I860_calli = _ida_allins.I860_calli

I860_fadd = _ida_allins.I860_fadd

I860_faddp = _ida_allins.I860_faddp

I860_faddz = _ida_allins.I860_faddz

I860_famov = _ida_allins.I860_famov

I860_fiadd = _ida_allins.I860_fiadd

I860_fisub = _ida_allins.I860_fisub

I860_fix = _ida_allins.I860_fix

I860_fld = _ida_allins.I860_fld

I860_flush = _ida_allins.I860_flush

I860_fmlow_dd = _ida_allins.I860_fmlow_dd

I860_fmul = _ida_allins.I860_fmul

I860_form = _ida_allins.I860_form

I860_frcp = _ida_allins.I860_frcp

I860_frsqr = _ida_allins.I860_frsqr

I860_fst = _ida_allins.I860_fst

I860_fsub = _ida_allins.I860_fsub

I860_ftrunc = _ida_allins.I860_ftrunc

I860_fxfr = _ida_allins.I860_fxfr

I860_fzchkl = _ida_allins.I860_fzchkl

I860_fzchks = _ida_allins.I860_fzchks

I860_introvr = _ida_allins.I860_introvr

I860_ixfr = _ida_allins.I860_ixfr

I860_ld_c = _ida_allins.I860_ld_c

I860_ld = _ida_allins.I860_ld

I860_ldint = _ida_allins.I860_ldint

I860_ldio = _ida_allins.I860_ldio

I860_lock = _ida_allins.I860_lock

I860_or = _ida_allins.I860_or

I860_orh = _ida_allins.I860_orh

I860_pfadd = _ida_allins.I860_pfadd

I860_pfaddp = _ida_allins.I860_pfaddp

I860_pfaddz = _ida_allins.I860_pfaddz

I860_pfamov = _ida_allins.I860_pfamov

I860_pfeq = _ida_allins.I860_pfeq

I860_pfgt = _ida_allins.I860_pfgt

I860_pfiadd = _ida_allins.I860_pfiadd

I860_pfisub = _ida_allins.I860_pfisub

I860_pfix = _ida_allins.I860_pfix

I860_pfld = _ida_allins.I860_pfld

I860_pfle = _ida_allins.I860_pfle

I860_pfmul = _ida_allins.I860_pfmul

I860_pfmul3_dd = _ida_allins.I860_pfmul3_dd

I860_pform = _ida_allins.I860_pform

I860_pfsub = _ida_allins.I860_pfsub

I860_pftrunc = _ida_allins.I860_pftrunc

I860_pfzchkl = _ida_allins.I860_pfzchkl

I860_pfzchks = _ida_allins.I860_pfzchks

I860_pst_d = _ida_allins.I860_pst_d

I860_scyc = _ida_allins.I860_scyc

I860_shl = _ida_allins.I860_shl

I860_shr = _ida_allins.I860_shr

I860_shra = _ida_allins.I860_shra

I860_shrd = _ida_allins.I860_shrd

I860_st_c = _ida_allins.I860_st_c

I860_st = _ida_allins.I860_st

I860_stio = _ida_allins.I860_stio

I860_subs = _ida_allins.I860_subs

I860_subu = _ida_allins.I860_subu

I860_trap = _ida_allins.I860_trap

I860_unlock = _ida_allins.I860_unlock

I860_xor = _ida_allins.I860_xor

I860_xorh = _ida_allins.I860_xorh

I860_r2p1 = _ida_allins.I860_r2p1

I860_r2pt = _ida_allins.I860_r2pt

I860_r2ap1 = _ida_allins.I860_r2ap1

I860_r2apt = _ida_allins.I860_r2apt

I860_i2p1 = _ida_allins.I860_i2p1

I860_i2pt = _ida_allins.I860_i2pt

I860_i2ap1 = _ida_allins.I860_i2ap1

I860_i2apt = _ida_allins.I860_i2apt

I860_rat1p2 = _ida_allins.I860_rat1p2

I860_m12apm = _ida_allins.I860_m12apm

I860_ra1p2 = _ida_allins.I860_ra1p2

I860_m12ttpa = _ida_allins.I860_m12ttpa

I860_iat1p2 = _ida_allins.I860_iat1p2

I860_m12tpm = _ida_allins.I860_m12tpm

I860_ia1p2 = _ida_allins.I860_ia1p2

I860_m12tpa = _ida_allins.I860_m12tpa

I860_r2s1 = _ida_allins.I860_r2s1

I860_r2st = _ida_allins.I860_r2st

I860_r2as1 = _ida_allins.I860_r2as1

I860_r2ast = _ida_allins.I860_r2ast

I860_i2s1 = _ida_allins.I860_i2s1

I860_i2st = _ida_allins.I860_i2st

I860_i2as1 = _ida_allins.I860_i2as1

I860_i2ast = _ida_allins.I860_i2ast

I860_rat1s2 = _ida_allins.I860_rat1s2

I860_m12asm = _ida_allins.I860_m12asm

I860_ra1s2 = _ida_allins.I860_ra1s2

I860_m12ttsa = _ida_allins.I860_m12ttsa

I860_iat1s2 = _ida_allins.I860_iat1s2

I860_m12tsm = _ida_allins.I860_m12tsm

I860_ia1s2 = _ida_allins.I860_ia1s2

I860_m12tsa = _ida_allins.I860_m12tsa

I860_mr2p1 = _ida_allins.I860_mr2p1

I860_mr2pt = _ida_allins.I860_mr2pt

I860_mr2mp1 = _ida_allins.I860_mr2mp1

I860_mr2mpt = _ida_allins.I860_mr2mpt

I860_mi2p1 = _ida_allins.I860_mi2p1

I860_mi2pt = _ida_allins.I860_mi2pt

I860_mi2mp1 = _ida_allins.I860_mi2mp1

I860_mi2mpt = _ida_allins.I860_mi2mpt

I860_mrmt1p2 = _ida_allins.I860_mrmt1p2

I860_mm12mpm = _ida_allins.I860_mm12mpm

I860_mrm1p2 = _ida_allins.I860_mrm1p2

I860_mm12ttpm = _ida_allins.I860_mm12ttpm

I860_mimt1p2 = _ida_allins.I860_mimt1p2

I860_mm12tpm = _ida_allins.I860_mm12tpm

I860_mim1p2 = _ida_allins.I860_mim1p2

I860_mr2s1 = _ida_allins.I860_mr2s1

I860_mr2st = _ida_allins.I860_mr2st

I860_mr2ms1 = _ida_allins.I860_mr2ms1

I860_mr2mst = _ida_allins.I860_mr2mst

I860_mi2s1 = _ida_allins.I860_mi2s1

I860_mi2st = _ida_allins.I860_mi2st

I860_mi2ms1 = _ida_allins.I860_mi2ms1

I860_mi2mst = _ida_allins.I860_mi2mst

I860_mrmt1s2 = _ida_allins.I860_mrmt1s2

I860_mm12msm = _ida_allins.I860_mm12msm

I860_mrm1s2 = _ida_allins.I860_mrm1s2

I860_mm12ttsm = _ida_allins.I860_mm12ttsm

I860_mimt1s2 = _ida_allins.I860_mimt1s2

I860_mm12tsm = _ida_allins.I860_mm12tsm

I860_mim1s2 = _ida_allins.I860_mim1s2

I860_last = _ida_allins.I860_last

I51_null = _ida_allins.I51_null

I51_acall = _ida_allins.I51_acall

I51_add = _ida_allins.I51_add

I51_addc = _ida_allins.I51_addc

I51_ajmp = _ida_allins.I51_ajmp

I51_anl = _ida_allins.I51_anl

I51_cjne = _ida_allins.I51_cjne

I51_clr = _ida_allins.I51_clr

I51_cpl = _ida_allins.I51_cpl

I51_da = _ida_allins.I51_da

I51_dec = _ida_allins.I51_dec

I51_div = _ida_allins.I51_div

I51_djnz = _ida_allins.I51_djnz

I51_inc = _ida_allins.I51_inc

I51_jb = _ida_allins.I51_jb

I51_jbc = _ida_allins.I51_jbc

I51_jc = _ida_allins.I51_jc

I51_jmp = _ida_allins.I51_jmp

I51_jnb = _ida_allins.I51_jnb

I51_jnc = _ida_allins.I51_jnc

I51_jnz = _ida_allins.I51_jnz

I51_jz = _ida_allins.I51_jz

I51_lcall = _ida_allins.I51_lcall

I51_ljmp = _ida_allins.I51_ljmp

I51_mov = _ida_allins.I51_mov

I51_movc = _ida_allins.I51_movc

I51_movx = _ida_allins.I51_movx

I51_mul = _ida_allins.I51_mul

I51_nop = _ida_allins.I51_nop

I51_orl = _ida_allins.I51_orl

I51_pop = _ida_allins.I51_pop

I51_push = _ida_allins.I51_push

I51_ret = _ida_allins.I51_ret

I51_reti = _ida_allins.I51_reti

I51_rl = _ida_allins.I51_rl

I51_rlc = _ida_allins.I51_rlc

I51_rr = _ida_allins.I51_rr

I51_rrc = _ida_allins.I51_rrc

I51_setb = _ida_allins.I51_setb

I51_sjmp = _ida_allins.I51_sjmp

I51_subb = _ida_allins.I51_subb

I51_swap = _ida_allins.I51_swap

I51_xch = _ida_allins.I51_xch

I51_xchd = _ida_allins.I51_xchd

I51_xrl = _ida_allins.I51_xrl

I51_jsle = _ida_allins.I51_jsle

I51_jsg = _ida_allins.I51_jsg

I51_jle = _ida_allins.I51_jle

I51_jg = _ida_allins.I51_jg

I51_jsl = _ida_allins.I51_jsl

I51_jsge = _ida_allins.I51_jsge

I51_je = _ida_allins.I51_je

I51_jne = _ida_allins.I51_jne

I51_trap = _ida_allins.I51_trap

I51_ejmp = _ida_allins.I51_ejmp

I51_ecall = _ida_allins.I51_ecall

I51_eret = _ida_allins.I51_eret

I51_movh = _ida_allins.I51_movh

I51_movz = _ida_allins.I51_movz

I51_movs = _ida_allins.I51_movs

I51_srl = _ida_allins.I51_srl

I51_sra = _ida_allins.I51_sra

I51_sll = _ida_allins.I51_sll

I51_sub = _ida_allins.I51_sub

I51_cmp = _ida_allins.I51_cmp

I51_emov = _ida_allins.I51_emov

I51_last = _ida_allins.I51_last

TMS_null = _ida_allins.TMS_null

TMS_abs = _ida_allins.TMS_abs

TMS_adcb = _ida_allins.TMS_adcb

TMS_add = _ida_allins.TMS_add

TMS_addb = _ida_allins.TMS_addb

TMS_addc = _ida_allins.TMS_addc

TMS_adds = _ida_allins.TMS_adds

TMS_addt = _ida_allins.TMS_addt

TMS_adrk = _ida_allins.TMS_adrk

TMS_and = _ida_allins.TMS_and

TMS_andb = _ida_allins.TMS_andb

TMS_apac = _ida_allins.TMS_apac

TMS_apl = _ida_allins.TMS_apl

TMS_apl2 = _ida_allins.TMS_apl2

TMS_b = _ida_allins.TMS_b

TMS_bacc = _ida_allins.TMS_bacc

TMS_baccd = _ida_allins.TMS_baccd

TMS_banz = _ida_allins.TMS_banz

TMS_banzd = _ida_allins.TMS_banzd

TMS_bcnd = _ida_allins.TMS_bcnd

TMS_bcndd = _ida_allins.TMS_bcndd

TMS_bd = _ida_allins.TMS_bd

TMS_bit = _ida_allins.TMS_bit

TMS_bitt = _ida_allins.TMS_bitt

TMS_bldd = _ida_allins.TMS_bldd

TMS_bldp = _ida_allins.TMS_bldp

TMS_blpd = _ida_allins.TMS_blpd

TMS_bsar = _ida_allins.TMS_bsar

TMS_cala = _ida_allins.TMS_cala

TMS_calad = _ida_allins.TMS_calad

TMS_call = _ida_allins.TMS_call

TMS_calld = _ida_allins.TMS_calld

TMS_cc = _ida_allins.TMS_cc

TMS_ccd = _ida_allins.TMS_ccd

TMS_clrc = _ida_allins.TMS_clrc

TMS_cmpl = _ida_allins.TMS_cmpl

TMS_cmpr = _ida_allins.TMS_cmpr

TMS_cpl = _ida_allins.TMS_cpl

TMS_cpl2 = _ida_allins.TMS_cpl2

TMS_crgt = _ida_allins.TMS_crgt

TMS_crlt = _ida_allins.TMS_crlt

TMS_dmov = _ida_allins.TMS_dmov

TMS_estop = _ida_allins.TMS_estop

TMS_exar = _ida_allins.TMS_exar

TMS_idle = _ida_allins.TMS_idle

TMS_idle2 = _ida_allins.TMS_idle2

TMS_in = _ida_allins.TMS_in

TMS_intr = _ida_allins.TMS_intr

TMS_lacb = _ida_allins.TMS_lacb

TMS_lacc = _ida_allins.TMS_lacc

TMS_lacl = _ida_allins.TMS_lacl

TMS_lact = _ida_allins.TMS_lact

TMS_lamm = _ida_allins.TMS_lamm

TMS_lar = _ida_allins.TMS_lar

TMS_ldp = _ida_allins.TMS_ldp

TMS_lmmr = _ida_allins.TMS_lmmr

TMS_lph = _ida_allins.TMS_lph

TMS_lst = _ida_allins.TMS_lst

TMS_lt = _ida_allins.TMS_lt

TMS_lta = _ida_allins.TMS_lta

TMS_ltd = _ida_allins.TMS_ltd

TMS_ltp = _ida_allins.TMS_ltp

TMS_lts = _ida_allins.TMS_lts

TMS_mac = _ida_allins.TMS_mac

TMS_macd = _ida_allins.TMS_macd

TMS_madd = _ida_allins.TMS_madd

TMS_mads = _ida_allins.TMS_mads

TMS_mar = _ida_allins.TMS_mar

TMS_mpy = _ida_allins.TMS_mpy

TMS_mpya = _ida_allins.TMS_mpya

TMS_mpys = _ida_allins.TMS_mpys

TMS_mpyu = _ida_allins.TMS_mpyu

TMS_neg = _ida_allins.TMS_neg

TMS_nmi = _ida_allins.TMS_nmi

TMS_nop = _ida_allins.TMS_nop

TMS_norm = _ida_allins.TMS_norm

TMS_opl = _ida_allins.TMS_opl

TMS_opl2 = _ida_allins.TMS_opl2

TMS_or = _ida_allins.TMS_or

TMS_orb = _ida_allins.TMS_orb

TMS_out = _ida_allins.TMS_out

TMS_pac = _ida_allins.TMS_pac

TMS_pop = _ida_allins.TMS_pop

TMS_popd = _ida_allins.TMS_popd

TMS_pshd = _ida_allins.TMS_pshd

TMS_push = _ida_allins.TMS_push

TMS_ret = _ida_allins.TMS_ret

TMS_retc = _ida_allins.TMS_retc

TMS_retcd = _ida_allins.TMS_retcd

TMS_retd = _ida_allins.TMS_retd

TMS_rete = _ida_allins.TMS_rete

TMS_reti = _ida_allins.TMS_reti

TMS_rol = _ida_allins.TMS_rol

TMS_rolb = _ida_allins.TMS_rolb

TMS_ror = _ida_allins.TMS_ror

TMS_rorb = _ida_allins.TMS_rorb

TMS_rpt = _ida_allins.TMS_rpt

TMS_rptb = _ida_allins.TMS_rptb

TMS_rptz = _ida_allins.TMS_rptz

TMS_sacb = _ida_allins.TMS_sacb

TMS_sach = _ida_allins.TMS_sach

TMS_sacl = _ida_allins.TMS_sacl

TMS_samm = _ida_allins.TMS_samm

TMS_sar = _ida_allins.TMS_sar

TMS_sath = _ida_allins.TMS_sath

TMS_satl = _ida_allins.TMS_satl

TMS_sbb = _ida_allins.TMS_sbb

TMS_sbbb = _ida_allins.TMS_sbbb

TMS_sbrk = _ida_allins.TMS_sbrk

TMS_setc = _ida_allins.TMS_setc

TMS_sfl = _ida_allins.TMS_sfl

TMS_sflb = _ida_allins.TMS_sflb

TMS_sfr = _ida_allins.TMS_sfr

TMS_sfrb = _ida_allins.TMS_sfrb

TMS_smmr = _ida_allins.TMS_smmr

TMS_spac = _ida_allins.TMS_spac

TMS_sph = _ida_allins.TMS_sph

TMS_spl = _ida_allins.TMS_spl

TMS_splk = _ida_allins.TMS_splk

TMS_spm = _ida_allins.TMS_spm

TMS_sqra = _ida_allins.TMS_sqra

TMS_sqrs = _ida_allins.TMS_sqrs

TMS_sst = _ida_allins.TMS_sst

TMS_sub = _ida_allins.TMS_sub

TMS_subb = _ida_allins.TMS_subb

TMS_subc = _ida_allins.TMS_subc

TMS_subs = _ida_allins.TMS_subs

TMS_subt = _ida_allins.TMS_subt

TMS_tblr = _ida_allins.TMS_tblr

TMS_tblw = _ida_allins.TMS_tblw

TMS_trap = _ida_allins.TMS_trap

TMS_xc = _ida_allins.TMS_xc

TMS_xor = _ida_allins.TMS_xor

TMS_xorb = _ida_allins.TMS_xorb

TMS_xpl = _ida_allins.TMS_xpl

TMS_xpl2 = _ida_allins.TMS_xpl2

TMS_zalr = _ida_allins.TMS_zalr

TMS_zap = _ida_allins.TMS_zap

TMS_zpr = _ida_allins.TMS_zpr

TMS2_abs = _ida_allins.TMS2_abs

TMS2_add = _ida_allins.TMS2_add

TMS2_addc = _ida_allins.TMS2_addc

TMS2_addh = _ida_allins.TMS2_addh

TMS2_addk = _ida_allins.TMS2_addk

TMS2_adds = _ida_allins.TMS2_adds

TMS2_addt = _ida_allins.TMS2_addt

TMS2_adlk = _ida_allins.TMS2_adlk

TMS2_adrk = _ida_allins.TMS2_adrk

TMS2_and = _ida_allins.TMS2_and

TMS2_andk = _ida_allins.TMS2_andk

TMS2_apac = _ida_allins.TMS2_apac

TMS2_b = _ida_allins.TMS2_b

TMS2_bacc = _ida_allins.TMS2_bacc

TMS2_banz = _ida_allins.TMS2_banz

TMS2_bbnz = _ida_allins.TMS2_bbnz

TMS2_bbz = _ida_allins.TMS2_bbz

TMS2_bc = _ida_allins.TMS2_bc

TMS2_bgez = _ida_allins.TMS2_bgez

TMS2_bgz = _ida_allins.TMS2_bgz

TMS2_bioz = _ida_allins.TMS2_bioz

TMS2_bit = _ida_allins.TMS2_bit

TMS2_bitt = _ida_allins.TMS2_bitt

TMS2_blez = _ida_allins.TMS2_blez

TMS2_blkd = _ida_allins.TMS2_blkd

TMS2_blkp = _ida_allins.TMS2_blkp

TMS2_blz = _ida_allins.TMS2_blz

TMS2_bnc = _ida_allins.TMS2_bnc

TMS2_bnv = _ida_allins.TMS2_bnv

TMS2_bnz = _ida_allins.TMS2_bnz

TMS2_bv = _ida_allins.TMS2_bv

TMS2_bz = _ida_allins.TMS2_bz

TMS2_cala = _ida_allins.TMS2_cala

TMS2_call = _ida_allins.TMS2_call

TMS2_cmpl = _ida_allins.TMS2_cmpl

TMS2_cmpr = _ida_allins.TMS2_cmpr

TMS2_cnfd = _ida_allins.TMS2_cnfd

TMS2_cnfp = _ida_allins.TMS2_cnfp

TMS2_conf = _ida_allins.TMS2_conf

TMS2_dint = _ida_allins.TMS2_dint

TMS2_dmov = _ida_allins.TMS2_dmov

TMS2_eint = _ida_allins.TMS2_eint

TMS2_fort = _ida_allins.TMS2_fort

TMS2_idle = _ida_allins.TMS2_idle

TMS2_in = _ida_allins.TMS2_in

TMS2_lac = _ida_allins.TMS2_lac

TMS2_lack = _ida_allins.TMS2_lack

TMS2_lact = _ida_allins.TMS2_lact

TMS2_lalk = _ida_allins.TMS2_lalk

TMS2_lar = _ida_allins.TMS2_lar

TMS2_lark = _ida_allins.TMS2_lark

TMS2_larp = _ida_allins.TMS2_larp

TMS2_ldp = _ida_allins.TMS2_ldp

TMS2_ldpk = _ida_allins.TMS2_ldpk

TMS2_lph = _ida_allins.TMS2_lph

TMS2_lrlk = _ida_allins.TMS2_lrlk

TMS2_lst = _ida_allins.TMS2_lst

TMS2_lst1 = _ida_allins.TMS2_lst1

TMS2_lt = _ida_allins.TMS2_lt

TMS2_lta = _ida_allins.TMS2_lta

TMS2_ltd = _ida_allins.TMS2_ltd

TMS2_ltp = _ida_allins.TMS2_ltp

TMS2_lts = _ida_allins.TMS2_lts

TMS2_mac = _ida_allins.TMS2_mac

TMS2_macd = _ida_allins.TMS2_macd

TMS2_mar = _ida_allins.TMS2_mar

TMS2_mpy = _ida_allins.TMS2_mpy

TMS2_mpya = _ida_allins.TMS2_mpya

TMS2_mpyk = _ida_allins.TMS2_mpyk

TMS2_mpys = _ida_allins.TMS2_mpys

TMS2_mpyu = _ida_allins.TMS2_mpyu

TMS2_neg = _ida_allins.TMS2_neg

TMS2_nop = _ida_allins.TMS2_nop

TMS2_norm = _ida_allins.TMS2_norm

TMS2_or = _ida_allins.TMS2_or

TMS2_ork = _ida_allins.TMS2_ork

TMS2_out = _ida_allins.TMS2_out

TMS2_pac = _ida_allins.TMS2_pac

TMS2_pop = _ida_allins.TMS2_pop

TMS2_popd = _ida_allins.TMS2_popd

TMS2_pshd = _ida_allins.TMS2_pshd

TMS2_push = _ida_allins.TMS2_push

TMS2_rc = _ida_allins.TMS2_rc

TMS2_ret = _ida_allins.TMS2_ret

TMS2_rfsm = _ida_allins.TMS2_rfsm

TMS2_rhm = _ida_allins.TMS2_rhm

TMS2_rol = _ida_allins.TMS2_rol

TMS2_ror = _ida_allins.TMS2_ror

TMS2_rovm = _ida_allins.TMS2_rovm

TMS2_rpt = _ida_allins.TMS2_rpt

TMS2_rptk = _ida_allins.TMS2_rptk

TMS2_rsxm = _ida_allins.TMS2_rsxm

TMS2_rtc = _ida_allins.TMS2_rtc

TMS2_rtxm = _ida_allins.TMS2_rtxm

TMS2_rxf = _ida_allins.TMS2_rxf

TMS2_sach = _ida_allins.TMS2_sach

TMS2_sacl = _ida_allins.TMS2_sacl

TMS2_sar = _ida_allins.TMS2_sar

TMS2_sblk = _ida_allins.TMS2_sblk

TMS2_sbrk = _ida_allins.TMS2_sbrk

TMS2_sc = _ida_allins.TMS2_sc

TMS2_sfl = _ida_allins.TMS2_sfl

TMS2_sfr = _ida_allins.TMS2_sfr

TMS2_sfsm = _ida_allins.TMS2_sfsm

TMS2_shm = _ida_allins.TMS2_shm

TMS2_sovm = _ida_allins.TMS2_sovm

TMS2_spac = _ida_allins.TMS2_spac

TMS2_sph = _ida_allins.TMS2_sph

TMS2_spl = _ida_allins.TMS2_spl

TMS2_spm = _ida_allins.TMS2_spm

TMS2_sqra = _ida_allins.TMS2_sqra

TMS2_sqrs = _ida_allins.TMS2_sqrs

TMS2_sst = _ida_allins.TMS2_sst

TMS2_sst1 = _ida_allins.TMS2_sst1

TMS2_ssxm = _ida_allins.TMS2_ssxm

TMS2_stc = _ida_allins.TMS2_stc

TMS2_stxm = _ida_allins.TMS2_stxm

TMS2_sub = _ida_allins.TMS2_sub

TMS2_subb = _ida_allins.TMS2_subb

TMS2_subc = _ida_allins.TMS2_subc

TMS2_subh = _ida_allins.TMS2_subh

TMS2_subk = _ida_allins.TMS2_subk

TMS2_subs = _ida_allins.TMS2_subs

TMS2_subt = _ida_allins.TMS2_subt

TMS2_sxf = _ida_allins.TMS2_sxf

TMS2_tblr = _ida_allins.TMS2_tblr

TMS2_tblw = _ida_allins.TMS2_tblw

TMS2_trap = _ida_allins.TMS2_trap

TMS2_xor = _ida_allins.TMS2_xor

TMS2_xork = _ida_allins.TMS2_xork

TMS2_zac = _ida_allins.TMS2_zac

TMS2_zalh = _ida_allins.TMS2_zalh

TMS2_zalr = _ida_allins.TMS2_zalr

TMS2_zals = _ida_allins.TMS2_zals

TMS_last = _ida_allins.TMS_last

M65_null = _ida_allins.M65_null

M65_adc = _ida_allins.M65_adc

M65_anc = _ida_allins.M65_anc

M65_and = _ida_allins.M65_and

M65_ane = _ida_allins.M65_ane

M65_arr = _ida_allins.M65_arr

M65_asl = _ida_allins.M65_asl

M65_asr = _ida_allins.M65_asr

M65_bcc = _ida_allins.M65_bcc

M65_bcs = _ida_allins.M65_bcs

M65_beq = _ida_allins.M65_beq

M65_bit = _ida_allins.M65_bit

M65_bmi = _ida_allins.M65_bmi

M65_bne = _ida_allins.M65_bne

M65_bpl = _ida_allins.M65_bpl

M65_brk = _ida_allins.M65_brk

M65_bvc = _ida_allins.M65_bvc

M65_bvs = _ida_allins.M65_bvs

M65_clc = _ida_allins.M65_clc

M65_cld = _ida_allins.M65_cld

M65_cli = _ida_allins.M65_cli

M65_clv = _ida_allins.M65_clv

M65_cmp = _ida_allins.M65_cmp

M65_cpx = _ida_allins.M65_cpx

M65_cpy = _ida_allins.M65_cpy

M65_dcp = _ida_allins.M65_dcp

M65_dec = _ida_allins.M65_dec

M65_dex = _ida_allins.M65_dex

M65_dey = _ida_allins.M65_dey

M65_eor = _ida_allins.M65_eor

M65_inc = _ida_allins.M65_inc

M65_inx = _ida_allins.M65_inx

M65_iny = _ida_allins.M65_iny

M65_isb = _ida_allins.M65_isb

M65_jmp = _ida_allins.M65_jmp

M65_jmpi = _ida_allins.M65_jmpi

M65_jsr = _ida_allins.M65_jsr

M65_lae = _ida_allins.M65_lae

M65_lax = _ida_allins.M65_lax

M65_lda = _ida_allins.M65_lda

M65_ldx = _ida_allins.M65_ldx

M65_ldy = _ida_allins.M65_ldy

M65_lsr = _ida_allins.M65_lsr

M65_lxa = _ida_allins.M65_lxa

M65_nop = _ida_allins.M65_nop

M65_ora = _ida_allins.M65_ora

M65_pha = _ida_allins.M65_pha

M65_php = _ida_allins.M65_php

M65_pla = _ida_allins.M65_pla

M65_plp = _ida_allins.M65_plp

M65_rla = _ida_allins.M65_rla

M65_rol = _ida_allins.M65_rol

M65_ror = _ida_allins.M65_ror

M65_rra = _ida_allins.M65_rra

M65_rti = _ida_allins.M65_rti

M65_rts = _ida_allins.M65_rts

M65_sax = _ida_allins.M65_sax

M65_sbc = _ida_allins.M65_sbc

M65_sbx = _ida_allins.M65_sbx

M65_sec = _ida_allins.M65_sec

M65_sed = _ida_allins.M65_sed

M65_sei = _ida_allins.M65_sei

M65_sha = _ida_allins.M65_sha

M65_shs = _ida_allins.M65_shs

M65_shx = _ida_allins.M65_shx

M65_shy = _ida_allins.M65_shy

M65_slo = _ida_allins.M65_slo

M65_sre = _ida_allins.M65_sre

M65_sta = _ida_allins.M65_sta

M65_stx = _ida_allins.M65_stx

M65_sty = _ida_allins.M65_sty

M65_tax = _ida_allins.M65_tax

M65_tay = _ida_allins.M65_tay

M65_tsx = _ida_allins.M65_tsx

M65_txa = _ida_allins.M65_txa

M65_txs = _ida_allins.M65_txs

M65_tya = _ida_allins.M65_tya

M65_bbr0 = _ida_allins.M65_bbr0

M65_bbr1 = _ida_allins.M65_bbr1

M65_bbr2 = _ida_allins.M65_bbr2

M65_bbr3 = _ida_allins.M65_bbr3

M65_bbr4 = _ida_allins.M65_bbr4

M65_bbr5 = _ida_allins.M65_bbr5

M65_bbr6 = _ida_allins.M65_bbr6

M65_bbr7 = _ida_allins.M65_bbr7

M65_bbs0 = _ida_allins.M65_bbs0

M65_bbs1 = _ida_allins.M65_bbs1

M65_bbs2 = _ida_allins.M65_bbs2

M65_bbs3 = _ida_allins.M65_bbs3

M65_bbs4 = _ida_allins.M65_bbs4

M65_bbs5 = _ida_allins.M65_bbs5

M65_bbs6 = _ida_allins.M65_bbs6

M65_bbs7 = _ida_allins.M65_bbs7

M65_rmb0 = _ida_allins.M65_rmb0

M65_rmb1 = _ida_allins.M65_rmb1

M65_rmb2 = _ida_allins.M65_rmb2

M65_rmb3 = _ida_allins.M65_rmb3

M65_rmb4 = _ida_allins.M65_rmb4

M65_rmb5 = _ida_allins.M65_rmb5

M65_rmb6 = _ida_allins.M65_rmb6

M65_rmb7 = _ida_allins.M65_rmb7

M65_smb0 = _ida_allins.M65_smb0

M65_smb1 = _ida_allins.M65_smb1

M65_smb2 = _ida_allins.M65_smb2

M65_smb3 = _ida_allins.M65_smb3

M65_smb4 = _ida_allins.M65_smb4

M65_smb5 = _ida_allins.M65_smb5

M65_smb6 = _ida_allins.M65_smb6

M65_smb7 = _ida_allins.M65_smb7

M65_stz = _ida_allins.M65_stz

M65_tsb = _ida_allins.M65_tsb

M65_trb = _ida_allins.M65_trb

M65_phy = _ida_allins.M65_phy

M65_ply = _ida_allins.M65_ply

M65_phx = _ida_allins.M65_phx

M65_plx = _ida_allins.M65_plx

M65_bra = _ida_allins.M65_bra

M65_wai = _ida_allins.M65_wai

M65_stp = _ida_allins.M65_stp

M65_last = _ida_allins.M65_last

M65816_null = _ida_allins.M65816_null

M65816_adc = _ida_allins.M65816_adc

M65816_and = _ida_allins.M65816_and

M65816_asl = _ida_allins.M65816_asl

M65816_bcc = _ida_allins.M65816_bcc

M65816_bcs = _ida_allins.M65816_bcs

M65816_beq = _ida_allins.M65816_beq

M65816_bit = _ida_allins.M65816_bit

M65816_bmi = _ida_allins.M65816_bmi

M65816_bne = _ida_allins.M65816_bne

M65816_bpl = _ida_allins.M65816_bpl

M65816_bra = _ida_allins.M65816_bra

M65816_brk = _ida_allins.M65816_brk

M65816_brl = _ida_allins.M65816_brl

M65816_bvc = _ida_allins.M65816_bvc

M65816_bvs = _ida_allins.M65816_bvs

M65816_clc = _ida_allins.M65816_clc

M65816_cld = _ida_allins.M65816_cld

M65816_cli = _ida_allins.M65816_cli

M65816_clv = _ida_allins.M65816_clv

M65816_cmp = _ida_allins.M65816_cmp

M65816_cop = _ida_allins.M65816_cop

M65816_cpx = _ida_allins.M65816_cpx

M65816_cpy = _ida_allins.M65816_cpy

M65816_dec = _ida_allins.M65816_dec

M65816_dex = _ida_allins.M65816_dex

M65816_dey = _ida_allins.M65816_dey

M65816_eor = _ida_allins.M65816_eor

M65816_inc = _ida_allins.M65816_inc

M65816_inx = _ida_allins.M65816_inx

M65816_iny = _ida_allins.M65816_iny

M65816_jml = _ida_allins.M65816_jml

M65816_jmp = _ida_allins.M65816_jmp

M65816_jsl = _ida_allins.M65816_jsl

M65816_jsr = _ida_allins.M65816_jsr

M65816_lda = _ida_allins.M65816_lda

M65816_ldx = _ida_allins.M65816_ldx

M65816_ldy = _ida_allins.M65816_ldy

M65816_lsr = _ida_allins.M65816_lsr

M65816_mvn = _ida_allins.M65816_mvn

M65816_mvp = _ida_allins.M65816_mvp

M65816_nop = _ida_allins.M65816_nop

M65816_ora = _ida_allins.M65816_ora

M65816_pea = _ida_allins.M65816_pea

M65816_pei = _ida_allins.M65816_pei

M65816_per = _ida_allins.M65816_per

M65816_pha = _ida_allins.M65816_pha

M65816_phb = _ida_allins.M65816_phb

M65816_phd = _ida_allins.M65816_phd

M65816_phk = _ida_allins.M65816_phk

M65816_php = _ida_allins.M65816_php

M65816_phx = _ida_allins.M65816_phx

M65816_phy = _ida_allins.M65816_phy

M65816_pla = _ida_allins.M65816_pla

M65816_plb = _ida_allins.M65816_plb

M65816_pld = _ida_allins.M65816_pld

M65816_plp = _ida_allins.M65816_plp

M65816_plx = _ida_allins.M65816_plx

M65816_ply = _ida_allins.M65816_ply

M65816_rep = _ida_allins.M65816_rep

M65816_rol = _ida_allins.M65816_rol

M65816_ror = _ida_allins.M65816_ror

M65816_rti = _ida_allins.M65816_rti

M65816_rtl = _ida_allins.M65816_rtl

M65816_rts = _ida_allins.M65816_rts

M65816_sbc = _ida_allins.M65816_sbc

M65816_sec = _ida_allins.M65816_sec

M65816_sed = _ida_allins.M65816_sed

M65816_sei = _ida_allins.M65816_sei

M65816_sep = _ida_allins.M65816_sep

M65816_sta = _ida_allins.M65816_sta

M65816_stp = _ida_allins.M65816_stp

M65816_stx = _ida_allins.M65816_stx

M65816_sty = _ida_allins.M65816_sty

M65816_stz = _ida_allins.M65816_stz

M65816_tax = _ida_allins.M65816_tax

M65816_tay = _ida_allins.M65816_tay

M65816_tcd = _ida_allins.M65816_tcd

M65816_tcs = _ida_allins.M65816_tcs

M65816_tdc = _ida_allins.M65816_tdc

M65816_trb = _ida_allins.M65816_trb

M65816_tsb = _ida_allins.M65816_tsb

M65816_tsc = _ida_allins.M65816_tsc

M65816_tsx = _ida_allins.M65816_tsx

M65816_txa = _ida_allins.M65816_txa

M65816_txs = _ida_allins.M65816_txs

M65816_txy = _ida_allins.M65816_txy

M65816_tya = _ida_allins.M65816_tya

M65816_tyx = _ida_allins.M65816_tyx

M65816_wai = _ida_allins.M65816_wai

M65816_wdm = _ida_allins.M65816_wdm

M65816_xba = _ida_allins.M65816_xba

M65816_xce = _ida_allins.M65816_xce

M65816_last = _ida_allins.M65816_last

pdp_null = _ida_allins.pdp_null

pdp_halt = _ida_allins.pdp_halt

pdp_wait = _ida_allins.pdp_wait

pdp_rti = _ida_allins.pdp_rti

pdp_bpt = _ida_allins.pdp_bpt

pdp_iot = _ida_allins.pdp_iot

pdp_reset = _ida_allins.pdp_reset

pdp_rtt = _ida_allins.pdp_rtt

pdp_mfpt = _ida_allins.pdp_mfpt

pdp_jmp = _ida_allins.pdp_jmp

pdp_rts = _ida_allins.pdp_rts

pdp_spl = _ida_allins.pdp_spl

pdp_nop = _ida_allins.pdp_nop

pdp_clc = _ida_allins.pdp_clc

pdp_clv = _ida_allins.pdp_clv

pdp_clz = _ida_allins.pdp_clz

pdp_cln = _ida_allins.pdp_cln

pdp_ccc = _ida_allins.pdp_ccc

pdp_sec = _ida_allins.pdp_sec

pdp_sev = _ida_allins.pdp_sev

pdp_sez = _ida_allins.pdp_sez

pdp_sen = _ida_allins.pdp_sen

pdp_scc = _ida_allins.pdp_scc

pdp_swab = _ida_allins.pdp_swab

pdp_br = _ida_allins.pdp_br

pdp_bne = _ida_allins.pdp_bne

pdp_beq = _ida_allins.pdp_beq

pdp_bge = _ida_allins.pdp_bge

pdp_blt = _ida_allins.pdp_blt

pdp_bgt = _ida_allins.pdp_bgt

pdp_ble = _ida_allins.pdp_ble

pdp_jsr = _ida_allins.pdp_jsr

pdp_clr = _ida_allins.pdp_clr

pdp_com = _ida_allins.pdp_com

pdp_inc = _ida_allins.pdp_inc

pdp_dec = _ida_allins.pdp_dec

pdp_neg = _ida_allins.pdp_neg

pdp_adc = _ida_allins.pdp_adc

pdp_sbc = _ida_allins.pdp_sbc

pdp_tst = _ida_allins.pdp_tst

pdp_ror = _ida_allins.pdp_ror

pdp_rol = _ida_allins.pdp_rol

pdp_asr = _ida_allins.pdp_asr

pdp_asl = _ida_allins.pdp_asl

pdp_mark = _ida_allins.pdp_mark

pdp_mfpi = _ida_allins.pdp_mfpi

pdp_mtpi = _ida_allins.pdp_mtpi

pdp_sxt = _ida_allins.pdp_sxt

pdp_mov = _ida_allins.pdp_mov

pdp_cmp = _ida_allins.pdp_cmp

pdp_bit = _ida_allins.pdp_bit

pdp_bic = _ida_allins.pdp_bic

pdp_bis = _ida_allins.pdp_bis

pdp_add = _ida_allins.pdp_add

pdp_sub = _ida_allins.pdp_sub

pdp_mul = _ida_allins.pdp_mul

pdp_div = _ida_allins.pdp_div

pdp_ash = _ida_allins.pdp_ash

pdp_ashc = _ida_allins.pdp_ashc

pdp_xor = _ida_allins.pdp_xor

pdp_fadd = _ida_allins.pdp_fadd

pdp_fsub = _ida_allins.pdp_fsub

pdp_fmul = _ida_allins.pdp_fmul

pdp_fdiv = _ida_allins.pdp_fdiv

pdp_sob = _ida_allins.pdp_sob

pdp_bpl = _ida_allins.pdp_bpl

pdp_bmi = _ida_allins.pdp_bmi

pdp_bhi = _ida_allins.pdp_bhi

pdp_blos = _ida_allins.pdp_blos

pdp_bvc = _ida_allins.pdp_bvc

pdp_bvs = _ida_allins.pdp_bvs

pdp_bcc = _ida_allins.pdp_bcc

pdp_bcs = _ida_allins.pdp_bcs

pdp_emt = _ida_allins.pdp_emt

pdp_trap = _ida_allins.pdp_trap

pdp_mtps = _ida_allins.pdp_mtps

pdp_mfpd = _ida_allins.pdp_mfpd

pdp_mtpd = _ida_allins.pdp_mtpd

pdp_mfps = _ida_allins.pdp_mfps

pdp_cfcc = _ida_allins.pdp_cfcc

pdp_setf = _ida_allins.pdp_setf

pdp_seti = _ida_allins.pdp_seti

pdp_setd = _ida_allins.pdp_setd

pdp_setl = _ida_allins.pdp_setl

pdp_ldfps = _ida_allins.pdp_ldfps

pdp_stfps = _ida_allins.pdp_stfps

pdp_stst = _ida_allins.pdp_stst

pdp_clrd = _ida_allins.pdp_clrd

pdp_tstd = _ida_allins.pdp_tstd

pdp_absd = _ida_allins.pdp_absd

pdp_negd = _ida_allins.pdp_negd

pdp_muld = _ida_allins.pdp_muld

pdp_modd = _ida_allins.pdp_modd

pdp_addd = _ida_allins.pdp_addd

pdp_ldd = _ida_allins.pdp_ldd

pdp_subd = _ida_allins.pdp_subd

pdp_cmpd = _ida_allins.pdp_cmpd

pdp_std = _ida_allins.pdp_std

pdp_divd = _ida_allins.pdp_divd

pdp_stexp = _ida_allins.pdp_stexp

pdp_stcdi = _ida_allins.pdp_stcdi

pdp_stcdf = _ida_allins.pdp_stcdf

pdp_ldexp = _ida_allins.pdp_ldexp

pdp_ldcif = _ida_allins.pdp_ldcif

pdp_ldcfd = _ida_allins.pdp_ldcfd

pdp_call = _ida_allins.pdp_call

pdp_return = _ida_allins.pdp_return

pdp_compcc = _ida_allins.pdp_compcc

pdp_last = _ida_allins.pdp_last

mc_null = _ida_allins.mc_null

mc_abcd = _ida_allins.mc_abcd

mc_add = _ida_allins.mc_add

mc_adda = _ida_allins.mc_adda

mc_addi = _ida_allins.mc_addi

mc_addq = _ida_allins.mc_addq

mc_addx = _ida_allins.mc_addx

mc_and = _ida_allins.mc_and

mc_andi = _ida_allins.mc_andi

mc_asl = _ida_allins.mc_asl

mc_asr = _ida_allins.mc_asr

mc_b = _ida_allins.mc_b

mc_bchg = _ida_allins.mc_bchg

mc_bclr = _ida_allins.mc_bclr

mc_bftst = _ida_allins.mc_bftst

mc_bfchg = _ida_allins.mc_bfchg

mc_bfclr = _ida_allins.mc_bfclr

mc_bfset = _ida_allins.mc_bfset

mc_bfextu = _ida_allins.mc_bfextu

mc_bfexts = _ida_allins.mc_bfexts

mc_bfffo = _ida_allins.mc_bfffo

mc_bfins = _ida_allins.mc_bfins

mc_bgnd = _ida_allins.mc_bgnd

mc_bkpt = _ida_allins.mc_bkpt

mc_bra = _ida_allins.mc_bra

mc_bset = _ida_allins.mc_bset

mc_bsr = _ida_allins.mc_bsr

mc_btst = _ida_allins.mc_btst

mc_callm = _ida_allins.mc_callm

mc_cas = _ida_allins.mc_cas

mc_cas2 = _ida_allins.mc_cas2

mc_chk = _ida_allins.mc_chk

mc_chk2 = _ida_allins.mc_chk2

mc_cinv = _ida_allins.mc_cinv

mc_clr = _ida_allins.mc_clr

mc_cmp = _ida_allins.mc_cmp

mc_cmp2 = _ida_allins.mc_cmp2

mc_cmpa = _ida_allins.mc_cmpa

mc_cmpi = _ida_allins.mc_cmpi

mc_cmpm = _ida_allins.mc_cmpm

mc_cpush = _ida_allins.mc_cpush

mc_db = _ida_allins.mc_db

mc_divs = _ida_allins.mc_divs

mc_divsl = _ida_allins.mc_divsl

mc_divu = _ida_allins.mc_divu

mc_divul = _ida_allins.mc_divul

mc_eor = _ida_allins.mc_eor

mc_eori = _ida_allins.mc_eori

mc_exg = _ida_allins.mc_exg

mc_ext = _ida_allins.mc_ext

mc_extb = _ida_allins.mc_extb

mc_fabs = _ida_allins.mc_fabs

mc_facos = _ida_allins.mc_facos

mc_fadd = _ida_allins.mc_fadd

mc_fasin = _ida_allins.mc_fasin

mc_fatan = _ida_allins.mc_fatan

mc_fatanh = _ida_allins.mc_fatanh

mc_fb = _ida_allins.mc_fb

mc_fcmp = _ida_allins.mc_fcmp

mc_fcos = _ida_allins.mc_fcos

mc_fcosh = _ida_allins.mc_fcosh

mc_fdabs = _ida_allins.mc_fdabs

mc_fdadd = _ida_allins.mc_fdadd

mc_fdb = _ida_allins.mc_fdb

mc_fddiv = _ida_allins.mc_fddiv

mc_fdiv = _ida_allins.mc_fdiv

mc_fdmove = _ida_allins.mc_fdmove

mc_fdmul = _ida_allins.mc_fdmul

mc_fdneg = _ida_allins.mc_fdneg

mc_fdsqrt = _ida_allins.mc_fdsqrt

mc_fdsub = _ida_allins.mc_fdsub

mc_fetox = _ida_allins.mc_fetox

mc_fetoxm1 = _ida_allins.mc_fetoxm1

mc_fgetexp = _ida_allins.mc_fgetexp

mc_fgetman = _ida_allins.mc_fgetman

mc_fint = _ida_allins.mc_fint

mc_fintrz = _ida_allins.mc_fintrz

mc_flog2 = _ida_allins.mc_flog2

mc_flog10 = _ida_allins.mc_flog10

mc_flogn = _ida_allins.mc_flogn

mc_flognp1 = _ida_allins.mc_flognp1

mc_fmod = _ida_allins.mc_fmod

mc_fmove = _ida_allins.mc_fmove

mc_fmovecr = _ida_allins.mc_fmovecr

mc_fmovem = _ida_allins.mc_fmovem

mc_fmul = _ida_allins.mc_fmul

mc_fneg = _ida_allins.mc_fneg

mc_fnop = _ida_allins.mc_fnop

mc_frem = _ida_allins.mc_frem

mc_frestore = _ida_allins.mc_frestore

mc_fs = _ida_allins.mc_fs

mc_fsabs = _ida_allins.mc_fsabs

mc_fsadd = _ida_allins.mc_fsadd

mc_fsave = _ida_allins.mc_fsave

mc_fscale = _ida_allins.mc_fscale

mc_fsdiv = _ida_allins.mc_fsdiv

mc_fsgldiv = _ida_allins.mc_fsgldiv

mc_fsglmul = _ida_allins.mc_fsglmul

mc_fsin = _ida_allins.mc_fsin

mc_fsincos = _ida_allins.mc_fsincos

mc_fsinh = _ida_allins.mc_fsinh

mc_fsmove = _ida_allins.mc_fsmove

mc_fsmul = _ida_allins.mc_fsmul

mc_fsneg = _ida_allins.mc_fsneg

mc_fsqrt = _ida_allins.mc_fsqrt

mc_fssqrt = _ida_allins.mc_fssqrt

mc_fssub = _ida_allins.mc_fssub

mc_fsub = _ida_allins.mc_fsub

mc_ftan = _ida_allins.mc_ftan

mc_ftanh = _ida_allins.mc_ftanh

mc_ftentox = _ida_allins.mc_ftentox

mc_ftrap = _ida_allins.mc_ftrap

mc_ftst = _ida_allins.mc_ftst

mc_ftwotox = _ida_allins.mc_ftwotox

mc_halt = _ida_allins.mc_halt

mc_illegal = _ida_allins.mc_illegal

mc_jmp = _ida_allins.mc_jmp

mc_jsr = _ida_allins.mc_jsr

mc_lea = _ida_allins.mc_lea

mc_link = _ida_allins.mc_link

mc_lpstop = _ida_allins.mc_lpstop

mc_lsl = _ida_allins.mc_lsl

mc_lsr = _ida_allins.mc_lsr

mc_mac = _ida_allins.mc_mac

mc_macl = _ida_allins.mc_macl

mc_move = _ida_allins.mc_move

mc_move16 = _ida_allins.mc_move16

mc_movea = _ida_allins.mc_movea

mc_movec = _ida_allins.mc_movec

mc_movem = _ida_allins.mc_movem

mc_movep = _ida_allins.mc_movep

mc_moveq = _ida_allins.mc_moveq

mc_moves = _ida_allins.mc_moves

mc_msac = _ida_allins.mc_msac

mc_msacl = _ida_allins.mc_msacl

mc_muls = _ida_allins.mc_muls

mc_mulu = _ida_allins.mc_mulu

mc_nbcd = _ida_allins.mc_nbcd

mc_neg = _ida_allins.mc_neg

mc_negx = _ida_allins.mc_negx

mc_nop = _ida_allins.mc_nop

mc_not = _ida_allins.mc_not

mc_or = _ida_allins.mc_or

mc_ori = _ida_allins.mc_ori

mc_pack = _ida_allins.mc_pack

mc_pea = _ida_allins.mc_pea

mc_pb = _ida_allins.mc_pb

mc_pdb = _ida_allins.mc_pdb

mc_pflush = _ida_allins.mc_pflush

mc_pflushr = _ida_allins.mc_pflushr

mc_ploadr = _ida_allins.mc_ploadr

mc_ploadw = _ida_allins.mc_ploadw

mc_pmove = _ida_allins.mc_pmove

mc_prestore = _ida_allins.mc_prestore

mc_psave = _ida_allins.mc_psave

mc_ps = _ida_allins.mc_ps

mc_ptestr = _ida_allins.mc_ptestr

mc_ptestw = _ida_allins.mc_ptestw

mc_ptrap = _ida_allins.mc_ptrap

mc_pulse = _ida_allins.mc_pulse

mc_pvalid = _ida_allins.mc_pvalid

mc_rol = _ida_allins.mc_rol

mc_ror = _ida_allins.mc_ror

mc_roxl = _ida_allins.mc_roxl

mc_roxr = _ida_allins.mc_roxr

mc_reset = _ida_allins.mc_reset

mc_rtd = _ida_allins.mc_rtd

mc_rte = _ida_allins.mc_rte

mc_rtm = _ida_allins.mc_rtm

mc_rtr = _ida_allins.mc_rtr

mc_rts = _ida_allins.mc_rts

mc_sbcd = _ida_allins.mc_sbcd

mc_s = _ida_allins.mc_s

mc_stop = _ida_allins.mc_stop

mc_sub = _ida_allins.mc_sub

mc_suba = _ida_allins.mc_suba

mc_subi = _ida_allins.mc_subi

mc_subq = _ida_allins.mc_subq

mc_subx = _ida_allins.mc_subx

mc_swap = _ida_allins.mc_swap

mc_tas = _ida_allins.mc_tas

mc_tbl = _ida_allins.mc_tbl

mc_trap = _ida_allins.mc_trap

mc_trapv = _ida_allins.mc_trapv

mc_tst = _ida_allins.mc_tst

mc_unlk = _ida_allins.mc_unlk

mc_unpk = _ida_allins.mc_unpk

mc_wddata = _ida_allins.mc_wddata

mc_wdebug = _ida_allins.mc_wdebug

mc_atrap = _ida_allins.mc_atrap

mc_bitrev = _ida_allins.mc_bitrev

mc_byterev = _ida_allins.mc_byterev

mc_ff1 = _ida_allins.mc_ff1

mc_intouch = _ida_allins.mc_intouch

mc_mov3q = _ida_allins.mc_mov3q

mc_mvs = _ida_allins.mc_mvs

mc_mvz = _ida_allins.mc_mvz

mc_sats = _ida_allins.mc_sats

mc_movclr = _ida_allins.mc_movclr

mc_maaac = _ida_allins.mc_maaac

mc_masac = _ida_allins.mc_masac

mc_msaac = _ida_allins.mc_msaac

mc_mssac = _ida_allins.mc_mssac

mc_remsl = _ida_allins.mc_remsl

mc_remul = _ida_allins.mc_remul

mc_last = _ida_allins.mc_last

mc8_null = _ida_allins.mc8_null

mc8_aba = _ida_allins.mc8_aba

mc8_ab = _ida_allins.mc8_ab

mc8_adc = _ida_allins.mc8_adc

mc8_add = _ida_allins.mc8_add

mc8_addd = _ida_allins.mc8_addd

mc8_ais = _ida_allins.mc8_ais

mc8_aix = _ida_allins.mc8_aix

mc8_and = _ida_allins.mc8_and

mc8_andcc = _ida_allins.mc8_andcc

mc8_asr = _ida_allins.mc8_asr

mc8_bcc = _ida_allins.mc8_bcc

mc8_bclr = _ida_allins.mc8_bclr

mc8_bcs = _ida_allins.mc8_bcs

mc8_beq = _ida_allins.mc8_beq

mc8_bge = _ida_allins.mc8_bge

mc8_bgt = _ida_allins.mc8_bgt

mc8_bhcc = _ida_allins.mc8_bhcc

mc8_bhcs = _ida_allins.mc8_bhcs

mc8_bhi = _ida_allins.mc8_bhi

mc8_bhs = _ida_allins.mc8_bhs

mc8_bih = _ida_allins.mc8_bih

mc8_bil = _ida_allins.mc8_bil

mc8_bit = _ida_allins.mc8_bit

mc8_ble = _ida_allins.mc8_ble

mc8_blo = _ida_allins.mc8_blo

mc8_bls = _ida_allins.mc8_bls

mc8_blt = _ida_allins.mc8_blt

mc8_bmc = _ida_allins.mc8_bmc

mc8_bmi = _ida_allins.mc8_bmi

mc8_bms = _ida_allins.mc8_bms

mc8_bne = _ida_allins.mc8_bne

mc8_bpl = _ida_allins.mc8_bpl

mc8_bra = _ida_allins.mc8_bra

mc8_brclr = _ida_allins.mc8_brclr

mc8_brn = _ida_allins.mc8_brn

mc8_brset = _ida_allins.mc8_brset

mc8_bset = _ida_allins.mc8_bset

mc8_bsr = _ida_allins.mc8_bsr

mc8_bvc = _ida_allins.mc8_bvc

mc8_bvs = _ida_allins.mc8_bvs

mc8_cba = _ida_allins.mc8_cba

mc8_cbeq = _ida_allins.mc8_cbeq

mc8_clc = _ida_allins.mc8_clc

mc8_cli = _ida_allins.mc8_cli

mc8_clr = _ida_allins.mc8_clr

mc8_clv = _ida_allins.mc8_clv

mc8_cmp = _ida_allins.mc8_cmp

mc8_com = _ida_allins.mc8_com

mc8_cp = _ida_allins.mc8_cp

mc8_cpd = _ida_allins.mc8_cpd

mc8_cphx = _ida_allins.mc8_cphx

mc8_cpx = _ida_allins.mc8_cpx

mc8_cwai = _ida_allins.mc8_cwai

mc8_daa = _ida_allins.mc8_daa

mc8_dbnz = _ida_allins.mc8_dbnz

mc8_de = _ida_allins.mc8_de

mc8_dec = _ida_allins.mc8_dec

mc8_des = _ida_allins.mc8_des

mc8_div = _ida_allins.mc8_div

mc8_eor = _ida_allins.mc8_eor

mc8_exg = _ida_allins.mc8_exg

mc8_fdiv = _ida_allins.mc8_fdiv

mc8_idiv = _ida_allins.mc8_idiv

mc8_in = _ida_allins.mc8_in

mc8_inc = _ida_allins.mc8_inc

mc8_ins = _ida_allins.mc8_ins

mc8_jmp = _ida_allins.mc8_jmp

mc8_jsr = _ida_allins.mc8_jsr

mc8_ld = _ida_allins.mc8_ld

mc8_lda = _ida_allins.mc8_lda

mc8_ldd = _ida_allins.mc8_ldd

mc8_ldhx = _ida_allins.mc8_ldhx

mc8_lds = _ida_allins.mc8_lds

mc8_ldx = _ida_allins.mc8_ldx

mc8_lea = _ida_allins.mc8_lea

mc8_lsl = _ida_allins.mc8_lsl

mc8_lsld = _ida_allins.mc8_lsld

mc8_lsr = _ida_allins.mc8_lsr

mc8_lsrd = _ida_allins.mc8_lsrd

mc8_mov = _ida_allins.mc8_mov

mc8_mul = _ida_allins.mc8_mul

mc8_neg = _ida_allins.mc8_neg

mc8_nop = _ida_allins.mc8_nop

mc8_nsa = _ida_allins.mc8_nsa

mc8_ora = _ida_allins.mc8_ora

mc8_orcc = _ida_allins.mc8_orcc

mc8_psh = _ida_allins.mc8_psh

mc8_psha = _ida_allins.mc8_psha

mc8_pshb = _ida_allins.mc8_pshb

mc8_pshh = _ida_allins.mc8_pshh

mc8_pshx = _ida_allins.mc8_pshx

mc8_pul = _ida_allins.mc8_pul

mc8_pula = _ida_allins.mc8_pula

mc8_pulb = _ida_allins.mc8_pulb

mc8_pulh = _ida_allins.mc8_pulh

mc8_pulx = _ida_allins.mc8_pulx

mc8_rol = _ida_allins.mc8_rol

mc8_ror = _ida_allins.mc8_ror

mc8_rsp = _ida_allins.mc8_rsp

mc8_rti = _ida_allins.mc8_rti

mc8_rts = _ida_allins.mc8_rts

mc8_sba = _ida_allins.mc8_sba

mc8_sbc = _ida_allins.mc8_sbc

mc8_sec = _ida_allins.mc8_sec

mc8_sei = _ida_allins.mc8_sei

mc8_sev = _ida_allins.mc8_sev

mc8_sex = _ida_allins.mc8_sex

mc8_slp = _ida_allins.mc8_slp

mc8_st = _ida_allins.mc8_st

mc8_sta = _ida_allins.mc8_sta

mc8_std = _ida_allins.mc8_std

mc8_sthx = _ida_allins.mc8_sthx

mc8_stop = _ida_allins.mc8_stop

mc8_sts = _ida_allins.mc8_sts

mc8_stx = _ida_allins.mc8_stx

mc8_sub = _ida_allins.mc8_sub

mc8_subd = _ida_allins.mc8_subd

mc8_swi = _ida_allins.mc8_swi

mc8_sync = _ida_allins.mc8_sync

mc8_tab = _ida_allins.mc8_tab

mc8_tap = _ida_allins.mc8_tap

mc8_tax = _ida_allins.mc8_tax

mc8_tba = _ida_allins.mc8_tba

mc8_test = _ida_allins.mc8_test

mc8_tfr = _ida_allins.mc8_tfr

mc8_tpa = _ida_allins.mc8_tpa

mc8_ts = _ida_allins.mc8_ts

mc8_tst = _ida_allins.mc8_tst

mc8_tsx = _ida_allins.mc8_tsx

mc8_txa = _ida_allins.mc8_txa

mc8_txs = _ida_allins.mc8_txs

mc8_tys = _ida_allins.mc8_tys

mc8_wai = _ida_allins.mc8_wai

mc8_wait = _ida_allins.mc8_wait

mc8_xgd = _ida_allins.mc8_xgd

mc8_1 = _ida_allins.mc8_1

mc8_2 = _ida_allins.mc8_2

mc8_os9 = _ida_allins.mc8_os9

mc8_aim = _ida_allins.mc8_aim

mc8_oim = _ida_allins.mc8_oim

mc8_eim = _ida_allins.mc8_eim

mc8_tim = _ida_allins.mc8_tim

mc8_bgnd = _ida_allins.mc8_bgnd

mc8_call = _ida_allins.mc8_call

mc8_rtc = _ida_allins.mc8_rtc

mc8_skip1 = _ida_allins.mc8_skip1

mc8_skip2 = _ida_allins.mc8_skip2

mc8_last = _ida_allins.mc8_last

j_nop = _ida_allins.j_nop

j_aconst_null = _ida_allins.j_aconst_null

j_iconst_m1 = _ida_allins.j_iconst_m1

j_iconst_0 = _ida_allins.j_iconst_0

j_iconst_1 = _ida_allins.j_iconst_1

j_iconst_2 = _ida_allins.j_iconst_2

j_iconst_3 = _ida_allins.j_iconst_3

j_iconst_4 = _ida_allins.j_iconst_4

j_iconst_5 = _ida_allins.j_iconst_5

j_lconst_0 = _ida_allins.j_lconst_0

j_lconst_1 = _ida_allins.j_lconst_1

j_fconst_0 = _ida_allins.j_fconst_0

j_fconst_1 = _ida_allins.j_fconst_1

j_fconst_2 = _ida_allins.j_fconst_2

j_dconst_0 = _ida_allins.j_dconst_0

j_dconst_1 = _ida_allins.j_dconst_1

j_bipush = _ida_allins.j_bipush

j_sipush = _ida_allins.j_sipush

j_ldc = _ida_allins.j_ldc

j_ldcw = _ida_allins.j_ldcw

j_ldc2w = _ida_allins.j_ldc2w

j_iload = _ida_allins.j_iload

j_lload = _ida_allins.j_lload

j_fload = _ida_allins.j_fload

j_dload = _ida_allins.j_dload

j_aload = _ida_allins.j_aload

j_iload_0 = _ida_allins.j_iload_0

j_iload_1 = _ida_allins.j_iload_1

j_iload_2 = _ida_allins.j_iload_2

j_iload_3 = _ida_allins.j_iload_3

j_lload_0 = _ida_allins.j_lload_0

j_lload_1 = _ida_allins.j_lload_1

j_lload_2 = _ida_allins.j_lload_2

j_lload_3 = _ida_allins.j_lload_3

j_fload_0 = _ida_allins.j_fload_0

j_fload_1 = _ida_allins.j_fload_1

j_fload_2 = _ida_allins.j_fload_2

j_fload_3 = _ida_allins.j_fload_3

j_dload_0 = _ida_allins.j_dload_0

j_dload_1 = _ida_allins.j_dload_1

j_dload_2 = _ida_allins.j_dload_2

j_dload_3 = _ida_allins.j_dload_3

j_aload_0 = _ida_allins.j_aload_0

j_aload_1 = _ida_allins.j_aload_1

j_aload_2 = _ida_allins.j_aload_2

j_aload_3 = _ida_allins.j_aload_3

j_iaload = _ida_allins.j_iaload

j_laload = _ida_allins.j_laload

j_faload = _ida_allins.j_faload

j_daload = _ida_allins.j_daload

j_aaload = _ida_allins.j_aaload

j_baload = _ida_allins.j_baload

j_caload = _ida_allins.j_caload

j_saload = _ida_allins.j_saload

j_istore = _ida_allins.j_istore

j_lstore = _ida_allins.j_lstore

j_fstore = _ida_allins.j_fstore

j_dstore = _ida_allins.j_dstore

j_astore = _ida_allins.j_astore

j_istore_0 = _ida_allins.j_istore_0

j_istore_1 = _ida_allins.j_istore_1

j_istore_2 = _ida_allins.j_istore_2

j_istore_3 = _ida_allins.j_istore_3

j_lstore_0 = _ida_allins.j_lstore_0

j_lstore_1 = _ida_allins.j_lstore_1

j_lstore_2 = _ida_allins.j_lstore_2

j_lstore_3 = _ida_allins.j_lstore_3

j_fstore_0 = _ida_allins.j_fstore_0

j_fstore_1 = _ida_allins.j_fstore_1

j_fstore_2 = _ida_allins.j_fstore_2

j_fstore_3 = _ida_allins.j_fstore_3

j_dstore_0 = _ida_allins.j_dstore_0

j_dstore_1 = _ida_allins.j_dstore_1

j_dstore_2 = _ida_allins.j_dstore_2

j_dstore_3 = _ida_allins.j_dstore_3

j_astore_0 = _ida_allins.j_astore_0

j_astore_1 = _ida_allins.j_astore_1

j_astore_2 = _ida_allins.j_astore_2

j_astore_3 = _ida_allins.j_astore_3

j_iastore = _ida_allins.j_iastore

j_lastore = _ida_allins.j_lastore

j_fastore = _ida_allins.j_fastore

j_dastore = _ida_allins.j_dastore

j_aastore = _ida_allins.j_aastore

j_bastore = _ida_allins.j_bastore

j_castore = _ida_allins.j_castore

j_sastore = _ida_allins.j_sastore

j_pop = _ida_allins.j_pop

j_pop2 = _ida_allins.j_pop2

j_dup = _ida_allins.j_dup

j_dup_x1 = _ida_allins.j_dup_x1

j_dup_x2 = _ida_allins.j_dup_x2

j_dup2 = _ida_allins.j_dup2

j_dup2_x1 = _ida_allins.j_dup2_x1

j_dup2_x2 = _ida_allins.j_dup2_x2

j_swap = _ida_allins.j_swap

j_iadd = _ida_allins.j_iadd

j_ladd = _ida_allins.j_ladd

j_fadd = _ida_allins.j_fadd

j_dadd = _ida_allins.j_dadd

j_isub = _ida_allins.j_isub

j_lsub = _ida_allins.j_lsub

j_fsub = _ida_allins.j_fsub

j_dsub = _ida_allins.j_dsub

j_imul = _ida_allins.j_imul

j_lmul = _ida_allins.j_lmul

j_fmul = _ida_allins.j_fmul

j_dmul = _ida_allins.j_dmul

j_idiv = _ida_allins.j_idiv

j_ldiv = _ida_allins.j_ldiv

j_fdiv = _ida_allins.j_fdiv

j_ddiv = _ida_allins.j_ddiv

j_irem = _ida_allins.j_irem

j_lrem = _ida_allins.j_lrem

j_frem = _ida_allins.j_frem

j_drem = _ida_allins.j_drem

j_ineg = _ida_allins.j_ineg

j_lneg = _ida_allins.j_lneg

j_fneg = _ida_allins.j_fneg

j_dneg = _ida_allins.j_dneg

j_ishl = _ida_allins.j_ishl

j_lshl = _ida_allins.j_lshl

j_ishr = _ida_allins.j_ishr

j_lshr = _ida_allins.j_lshr

j_iushr = _ida_allins.j_iushr

j_lushr = _ida_allins.j_lushr

j_iand = _ida_allins.j_iand

j_land = _ida_allins.j_land

j_ior = _ida_allins.j_ior

j_lor = _ida_allins.j_lor

j_ixor = _ida_allins.j_ixor

j_lxor = _ida_allins.j_lxor

j_iinc = _ida_allins.j_iinc

j_i2l = _ida_allins.j_i2l

j_i2f = _ida_allins.j_i2f

j_i2d = _ida_allins.j_i2d

j_l2i = _ida_allins.j_l2i

j_l2f = _ida_allins.j_l2f

j_l2d = _ida_allins.j_l2d

j_f2i = _ida_allins.j_f2i

j_f2l = _ida_allins.j_f2l

j_f2d = _ida_allins.j_f2d

j_d2i = _ida_allins.j_d2i

j_d2l = _ida_allins.j_d2l

j_d2f = _ida_allins.j_d2f

j_i2b = _ida_allins.j_i2b

j_i2c = _ida_allins.j_i2c

j_i2s = _ida_allins.j_i2s

j_lcmp = _ida_allins.j_lcmp

j_fcmpl = _ida_allins.j_fcmpl

j_fcmpg = _ida_allins.j_fcmpg

j_dcmpl = _ida_allins.j_dcmpl

j_dcmpg = _ida_allins.j_dcmpg

j_ifeq = _ida_allins.j_ifeq

j_ifne = _ida_allins.j_ifne

j_iflt = _ida_allins.j_iflt

j_ifge = _ida_allins.j_ifge

j_ifgt = _ida_allins.j_ifgt

j_ifle = _ida_allins.j_ifle

j_if_icmpeq = _ida_allins.j_if_icmpeq

j_if_icmpne = _ida_allins.j_if_icmpne

j_if_icmplt = _ida_allins.j_if_icmplt

j_if_icmpge = _ida_allins.j_if_icmpge

j_if_icmpgt = _ida_allins.j_if_icmpgt

j_if_icmple = _ida_allins.j_if_icmple

j_if_acmpeq = _ida_allins.j_if_acmpeq

j_if_acmpne = _ida_allins.j_if_acmpne

j_goto = _ida_allins.j_goto

j_jsr = _ida_allins.j_jsr

j_ret = _ida_allins.j_ret

j_tableswitch = _ida_allins.j_tableswitch

j_lookupswitch = _ida_allins.j_lookupswitch

j_ireturn = _ida_allins.j_ireturn

j_lreturn = _ida_allins.j_lreturn

j_freturn = _ida_allins.j_freturn

j_dreturn = _ida_allins.j_dreturn

j_areturn = _ida_allins.j_areturn

j_return = _ida_allins.j_return

j_getstatic = _ida_allins.j_getstatic

j_putstatic = _ida_allins.j_putstatic

j_getfield = _ida_allins.j_getfield

j_putfield = _ida_allins.j_putfield

j_invokevirtual = _ida_allins.j_invokevirtual

j_invokespecial = _ida_allins.j_invokespecial

j_invokestatic = _ida_allins.j_invokestatic

j_invokeinterface = _ida_allins.j_invokeinterface

j_invokedynamic = _ida_allins.j_invokedynamic

j_new = _ida_allins.j_new

j_newarray = _ida_allins.j_newarray

j_anewarray = _ida_allins.j_anewarray

j_arraylength = _ida_allins.j_arraylength

j_athrow = _ida_allins.j_athrow

j_checkcast = _ida_allins.j_checkcast

j_instanceof = _ida_allins.j_instanceof

j_monitorenter = _ida_allins.j_monitorenter

j_monitorexit = _ida_allins.j_monitorexit

j_wide = _ida_allins.j_wide

j_multianewarray = _ida_allins.j_multianewarray

j_ifnull = _ida_allins.j_ifnull

j_ifnonnull = _ida_allins.j_ifnonnull

j_goto_w = _ida_allins.j_goto_w

j_jsr_w = _ida_allins.j_jsr_w

j_breakpoint = _ida_allins.j_breakpoint

j_lastnorm = _ida_allins.j_lastnorm

j_a_invokesuper = _ida_allins.j_a_invokesuper

j_a_invokevirtualobject = _ida_allins.j_a_invokevirtualobject

j_a_invokeignored = _ida_allins.j_a_invokeignored

j_a_software = _ida_allins.j_a_software

j_a_hardware = _ida_allins.j_a_hardware

j_last = _ida_allins.j_last

j_ldc_quick = _ida_allins.j_ldc_quick

j_ldcw_quick = _ida_allins.j_ldcw_quick

j_ldc2w_quick = _ida_allins.j_ldc2w_quick

j_getfield_quick = _ida_allins.j_getfield_quick

j_putfield_quick = _ida_allins.j_putfield_quick

j_getfield2_quick = _ida_allins.j_getfield2_quick

j_putfield2_quick = _ida_allins.j_putfield2_quick

j_getstatic_quick = _ida_allins.j_getstatic_quick

j_putstatic_quick = _ida_allins.j_putstatic_quick

j_getstatic2_quick = _ida_allins.j_getstatic2_quick

j_putstatic2_quick = _ida_allins.j_putstatic2_quick

j_invokevirtual_quick = _ida_allins.j_invokevirtual_quick

j_invokenonvirtual_quick = _ida_allins.j_invokenonvirtual_quick

j_invokesuper_quick = _ida_allins.j_invokesuper_quick

j_invokestatic_quick = _ida_allins.j_invokestatic_quick

j_invokeinterface_quick = _ida_allins.j_invokeinterface_quick

j_invokevirtualobject_quick = _ida_allins.j_invokevirtualobject_quick

j_invokeignored_quick = _ida_allins.j_invokeignored_quick

j_new_quick = _ida_allins.j_new_quick

j_anewarray_quick = _ida_allins.j_anewarray_quick

j_multianewarray_quick = _ida_allins.j_multianewarray_quick

j_checkcast_quick = _ida_allins.j_checkcast_quick

j_instanceof_quick = _ida_allins.j_instanceof_quick

j_invokevirtual_quick_w = _ida_allins.j_invokevirtual_quick_w

j_getfield_quick_w = _ida_allins.j_getfield_quick_w

j_putfield_quick_w = _ida_allins.j_putfield_quick_w

j_quick_last = _ida_allins.j_quick_last

ARM_null = _ida_allins.ARM_null

ARM_ret = _ida_allins.ARM_ret

ARM_nop = _ida_allins.ARM_nop

ARM_b = _ida_allins.ARM_b

ARM_bl = _ida_allins.ARM_bl

ARM_asr = _ida_allins.ARM_asr

ARM_lsl = _ida_allins.ARM_lsl

ARM_lsr = _ida_allins.ARM_lsr

ARM_ror = _ida_allins.ARM_ror

ARM_neg = _ida_allins.ARM_neg

ARM_and = _ida_allins.ARM_and

ARM_eor = _ida_allins.ARM_eor

ARM_sub = _ida_allins.ARM_sub

ARM_rsb = _ida_allins.ARM_rsb

ARM_add = _ida_allins.ARM_add

ARM_adc = _ida_allins.ARM_adc

ARM_sbc = _ida_allins.ARM_sbc

ARM_rsc = _ida_allins.ARM_rsc

ARM_tst = _ida_allins.ARM_tst

ARM_teq = _ida_allins.ARM_teq

ARM_cmp = _ida_allins.ARM_cmp

ARM_cmn = _ida_allins.ARM_cmn

ARM_orr = _ida_allins.ARM_orr

ARM_mov = _ida_allins.ARM_mov

ARM_bic = _ida_allins.ARM_bic

ARM_mvn = _ida_allins.ARM_mvn

ARM_mrs = _ida_allins.ARM_mrs

ARM_msr = _ida_allins.ARM_msr

ARM_mul = _ida_allins.ARM_mul

ARM_mla = _ida_allins.ARM_mla

ARM_ldr = _ida_allins.ARM_ldr

ARM_ldrpc = _ida_allins.ARM_ldrpc

ARM_str = _ida_allins.ARM_str

ARM_ldm = _ida_allins.ARM_ldm

ARM_stm = _ida_allins.ARM_stm

ARM_swp = _ida_allins.ARM_swp

ARM_svc = _ida_allins.ARM_svc

ARM_smull = _ida_allins.ARM_smull

ARM_smlal = _ida_allins.ARM_smlal

ARM_umull = _ida_allins.ARM_umull

ARM_umlal = _ida_allins.ARM_umlal

ARM_bx = _ida_allins.ARM_bx

ARM_pop = _ida_allins.ARM_pop

ARM_push = _ida_allins.ARM_push

ARM_adr = _ida_allins.ARM_adr

ARM_bkpt = _ida_allins.ARM_bkpt

ARM_blx1 = _ida_allins.ARM_blx1

ARM_blx2 = _ida_allins.ARM_blx2

ARM_clz = _ida_allins.ARM_clz

ARM_ldrd = _ida_allins.ARM_ldrd

ARM_pld = _ida_allins.ARM_pld

ARM_qadd = _ida_allins.ARM_qadd

ARM_qdadd = _ida_allins.ARM_qdadd

ARM_qdsub = _ida_allins.ARM_qdsub

ARM_qsub = _ida_allins.ARM_qsub

ARM_smlabb = _ida_allins.ARM_smlabb

ARM_smlatb = _ida_allins.ARM_smlatb

ARM_smlabt = _ida_allins.ARM_smlabt

ARM_smlatt = _ida_allins.ARM_smlatt

ARM_smlalbb = _ida_allins.ARM_smlalbb

ARM_smlaltb = _ida_allins.ARM_smlaltb

ARM_smlalbt = _ida_allins.ARM_smlalbt

ARM_smlaltt = _ida_allins.ARM_smlaltt

ARM_smlawb = _ida_allins.ARM_smlawb

ARM_smulwb = _ida_allins.ARM_smulwb

ARM_smlawt = _ida_allins.ARM_smlawt

ARM_smulwt = _ida_allins.ARM_smulwt

ARM_smulbb = _ida_allins.ARM_smulbb

ARM_smultb = _ida_allins.ARM_smultb

ARM_smulbt = _ida_allins.ARM_smulbt

ARM_smultt = _ida_allins.ARM_smultt

ARM_strd = _ida_allins.ARM_strd

xScale_mia = _ida_allins.xScale_mia

xScale_miaph = _ida_allins.xScale_miaph

xScale_miabb = _ida_allins.xScale_miabb

xScale_miabt = _ida_allins.xScale_miabt

xScale_miatb = _ida_allins.xScale_miatb

xScale_miatt = _ida_allins.xScale_miatt

xScale_mar = _ida_allins.xScale_mar

xScale_mra = _ida_allins.xScale_mra

ARM_movl = _ida_allins.ARM_movl

ARM_adrl = _ida_allins.ARM_adrl

ARM_swbkpt = _ida_allins.ARM_swbkpt

ARM_cdp = _ida_allins.ARM_cdp

ARM_cdp2 = _ida_allins.ARM_cdp2

ARM_ldc = _ida_allins.ARM_ldc

ARM_ldc2 = _ida_allins.ARM_ldc2

ARM_stc = _ida_allins.ARM_stc

ARM_stc2 = _ida_allins.ARM_stc2

ARM_mrc = _ida_allins.ARM_mrc

ARM_mrc2 = _ida_allins.ARM_mrc2

ARM_mcr = _ida_allins.ARM_mcr

ARM_mcr2 = _ida_allins.ARM_mcr2

ARM_mcrr = _ida_allins.ARM_mcrr

ARM_mrrc = _ida_allins.ARM_mrrc

ARM_fabsd = _ida_allins.ARM_fabsd

ARM_fabss = _ida_allins.ARM_fabss

ARM_faddd = _ida_allins.ARM_faddd

ARM_fadds = _ida_allins.ARM_fadds

ARM_fcmpd = _ida_allins.ARM_fcmpd

ARM_fcmps = _ida_allins.ARM_fcmps

ARM_fcmped = _ida_allins.ARM_fcmped

ARM_fcmpes = _ida_allins.ARM_fcmpes

ARM_fcmpezd = _ida_allins.ARM_fcmpezd

ARM_fcmpezs = _ida_allins.ARM_fcmpezs

ARM_fcmpzd = _ida_allins.ARM_fcmpzd

ARM_fcmpzs = _ida_allins.ARM_fcmpzs

ARM_fcpyd = _ida_allins.ARM_fcpyd

ARM_fcpys = _ida_allins.ARM_fcpys

ARM_fcvtsd = _ida_allins.ARM_fcvtsd

ARM_fcvtds = _ida_allins.ARM_fcvtds

ARM_fdivd = _ida_allins.ARM_fdivd

ARM_fdivs = _ida_allins.ARM_fdivs

ARM_fldd = _ida_allins.ARM_fldd

ARM_flds = _ida_allins.ARM_flds

ARM_fldmd = _ida_allins.ARM_fldmd

ARM_fldms = _ida_allins.ARM_fldms

ARM_fldmx = _ida_allins.ARM_fldmx

ARM_fmacd = _ida_allins.ARM_fmacd

ARM_fmacs = _ida_allins.ARM_fmacs

ARM_fmscd = _ida_allins.ARM_fmscd

ARM_fmscs = _ida_allins.ARM_fmscs

ARM_fmstat = _ida_allins.ARM_fmstat

ARM_fmuld = _ida_allins.ARM_fmuld

ARM_fmuls = _ida_allins.ARM_fmuls

ARM_fnegd = _ida_allins.ARM_fnegd

ARM_fnegs = _ida_allins.ARM_fnegs

ARM_fnmacd = _ida_allins.ARM_fnmacd

ARM_fnmacs = _ida_allins.ARM_fnmacs

ARM_fnmscd = _ida_allins.ARM_fnmscd

ARM_fnmscs = _ida_allins.ARM_fnmscs

ARM_fnmuld = _ida_allins.ARM_fnmuld

ARM_fnmuls = _ida_allins.ARM_fnmuls

ARM_fsitod = _ida_allins.ARM_fsitod

ARM_fsitos = _ida_allins.ARM_fsitos

ARM_fsqrtd = _ida_allins.ARM_fsqrtd

ARM_fsqrts = _ida_allins.ARM_fsqrts

ARM_fstd = _ida_allins.ARM_fstd

ARM_fsts = _ida_allins.ARM_fsts

ARM_fstmd = _ida_allins.ARM_fstmd

ARM_fstms = _ida_allins.ARM_fstms

ARM_fstmx = _ida_allins.ARM_fstmx

ARM_fsubd = _ida_allins.ARM_fsubd

ARM_fsubs = _ida_allins.ARM_fsubs

ARM_ftosid = _ida_allins.ARM_ftosid

ARM_ftosis = _ida_allins.ARM_ftosis

ARM_ftosizd = _ida_allins.ARM_ftosizd

ARM_ftosizs = _ida_allins.ARM_ftosizs

ARM_ftouid = _ida_allins.ARM_ftouid

ARM_ftouis = _ida_allins.ARM_ftouis

ARM_ftouizd = _ida_allins.ARM_ftouizd

ARM_ftouizs = _ida_allins.ARM_ftouizs

ARM_fuitod = _ida_allins.ARM_fuitod

ARM_fuitos = _ida_allins.ARM_fuitos

ARM_fmdhr = _ida_allins.ARM_fmdhr

ARM_fmrdh = _ida_allins.ARM_fmrdh

ARM_fmdlr = _ida_allins.ARM_fmdlr

ARM_fmrdl = _ida_allins.ARM_fmrdl

ARM_fmxr = _ida_allins.ARM_fmxr

ARM_fmrx = _ida_allins.ARM_fmrx

ARM_fmsr = _ida_allins.ARM_fmsr

ARM_fmrs = _ida_allins.ARM_fmrs

ARM_fmdrr = _ida_allins.ARM_fmdrr

ARM_fmrrd = _ida_allins.ARM_fmrrd

ARM_fmsrr = _ida_allins.ARM_fmsrr

ARM_fmrrs = _ida_allins.ARM_fmrrs

ARM_bxj = _ida_allins.ARM_bxj

ARM_mcrr2 = _ida_allins.ARM_mcrr2

ARM_mrrc2 = _ida_allins.ARM_mrrc2

ARM_cps = _ida_allins.ARM_cps

ARM_cpsid = _ida_allins.ARM_cpsid

ARM_cpsie = _ida_allins.ARM_cpsie

ARM_ldrex = _ida_allins.ARM_ldrex

ARM_pkhbt = _ida_allins.ARM_pkhbt

ARM_pkhtb = _ida_allins.ARM_pkhtb

ARM_qadd16 = _ida_allins.ARM_qadd16

ARM_qadd8 = _ida_allins.ARM_qadd8

ARM_qaddsubx = _ida_allins.ARM_qaddsubx

ARM_qsub16 = _ida_allins.ARM_qsub16

ARM_qsub8 = _ida_allins.ARM_qsub8

ARM_qsubaddx = _ida_allins.ARM_qsubaddx

ARM_rev = _ida_allins.ARM_rev

ARM_rev16 = _ida_allins.ARM_rev16

ARM_revsh = _ida_allins.ARM_revsh

ARM_rfe = _ida_allins.ARM_rfe

ARM_sadd16 = _ida_allins.ARM_sadd16

ARM_sadd8 = _ida_allins.ARM_sadd8

ARM_saddsubx = _ida_allins.ARM_saddsubx

ARM_sel = _ida_allins.ARM_sel

ARM_setend = _ida_allins.ARM_setend

ARM_shadd16 = _ida_allins.ARM_shadd16

ARM_shadd8 = _ida_allins.ARM_shadd8

ARM_shaddsubx = _ida_allins.ARM_shaddsubx

ARM_shsub16 = _ida_allins.ARM_shsub16

ARM_shsub8 = _ida_allins.ARM_shsub8

ARM_shsubaddx = _ida_allins.ARM_shsubaddx

ARM_smlad = _ida_allins.ARM_smlad

ARM_smladx = _ida_allins.ARM_smladx

ARM_smuad = _ida_allins.ARM_smuad

ARM_smuadx = _ida_allins.ARM_smuadx

ARM_smlald = _ida_allins.ARM_smlald

ARM_smlaldx = _ida_allins.ARM_smlaldx

ARM_smlsd = _ida_allins.ARM_smlsd

ARM_smlsdx = _ida_allins.ARM_smlsdx

ARM_smusd = _ida_allins.ARM_smusd

ARM_smusdx = _ida_allins.ARM_smusdx

ARM_smlsld = _ida_allins.ARM_smlsld

ARM_smlsldx = _ida_allins.ARM_smlsldx

ARM_smmla = _ida_allins.ARM_smmla

ARM_smmlar = _ida_allins.ARM_smmlar

ARM_smmul = _ida_allins.ARM_smmul

ARM_smmulr = _ida_allins.ARM_smmulr

ARM_smmls = _ida_allins.ARM_smmls

ARM_smmlsr = _ida_allins.ARM_smmlsr

ARM_srs = _ida_allins.ARM_srs

ARM_ssat = _ida_allins.ARM_ssat

ARM_ssat16 = _ida_allins.ARM_ssat16

ARM_ssub16 = _ida_allins.ARM_ssub16

ARM_ssub8 = _ida_allins.ARM_ssub8

ARM_ssubaddx = _ida_allins.ARM_ssubaddx

ARM_strex = _ida_allins.ARM_strex

ARM_sxtab = _ida_allins.ARM_sxtab

ARM_sxtb = _ida_allins.ARM_sxtb

ARM_sxtab16 = _ida_allins.ARM_sxtab16

ARM_sxtb16 = _ida_allins.ARM_sxtb16

ARM_sxtah = _ida_allins.ARM_sxtah

ARM_sxth = _ida_allins.ARM_sxth

ARM_uadd16 = _ida_allins.ARM_uadd16

ARM_uadd8 = _ida_allins.ARM_uadd8

ARM_uaddsubx = _ida_allins.ARM_uaddsubx

ARM_uhadd16 = _ida_allins.ARM_uhadd16

ARM_uhadd8 = _ida_allins.ARM_uhadd8

ARM_uhaddsubx = _ida_allins.ARM_uhaddsubx

ARM_uhsub16 = _ida_allins.ARM_uhsub16

ARM_uhsub8 = _ida_allins.ARM_uhsub8

ARM_uhsubaddx = _ida_allins.ARM_uhsubaddx

ARM_umaal = _ida_allins.ARM_umaal

ARM_uqadd16 = _ida_allins.ARM_uqadd16

ARM_uqadd8 = _ida_allins.ARM_uqadd8

ARM_uqaddsubx = _ida_allins.ARM_uqaddsubx

ARM_uqsub16 = _ida_allins.ARM_uqsub16

ARM_uqsub8 = _ida_allins.ARM_uqsub8

ARM_uqsubaddx = _ida_allins.ARM_uqsubaddx

ARM_usada8 = _ida_allins.ARM_usada8

ARM_usad8 = _ida_allins.ARM_usad8

ARM_usat = _ida_allins.ARM_usat

ARM_usat16 = _ida_allins.ARM_usat16

ARM_usub16 = _ida_allins.ARM_usub16

ARM_usub8 = _ida_allins.ARM_usub8

ARM_usubaddx = _ida_allins.ARM_usubaddx

ARM_uxtab = _ida_allins.ARM_uxtab

ARM_uxtb = _ida_allins.ARM_uxtb

ARM_uxtab16 = _ida_allins.ARM_uxtab16

ARM_uxtb16 = _ida_allins.ARM_uxtb16

ARM_uxtah = _ida_allins.ARM_uxtah

ARM_uxth = _ida_allins.ARM_uxth

ARM_clrex = _ida_allins.ARM_clrex

ARM_ldrexb = _ida_allins.ARM_ldrexb

ARM_ldrexd = _ida_allins.ARM_ldrexd

ARM_ldrexh = _ida_allins.ARM_ldrexh

ARM_strexb = _ida_allins.ARM_strexb

ARM_strexd = _ida_allins.ARM_strexd

ARM_strexh = _ida_allins.ARM_strexh

ARM_yield = _ida_allins.ARM_yield

ARM_sev = _ida_allins.ARM_sev

ARM_wfe = _ida_allins.ARM_wfe

ARM_wfi = _ida_allins.ARM_wfi

ARM_smc = _ida_allins.ARM_smc

ARM_orn = _ida_allins.ARM_orn

ARM_movt = _ida_allins.ARM_movt

ARM_sbfx = _ida_allins.ARM_sbfx

ARM_ubfx = _ida_allins.ARM_ubfx

ARM_bfi = _ida_allins.ARM_bfi

ARM_bfc = _ida_allins.ARM_bfc

ARM_tbb = _ida_allins.ARM_tbb

ARM_tbh = _ida_allins.ARM_tbh

ARM_pli = _ida_allins.ARM_pli

ARM_rbit = _ida_allins.ARM_rbit

ARM_it = _ida_allins.ARM_it

ARM_mls = _ida_allins.ARM_mls

ARM_sdiv = _ida_allins.ARM_sdiv

ARM_udiv = _ida_allins.ARM_udiv

ARM_cbz = _ida_allins.ARM_cbz

ARM_cbnz = _ida_allins.ARM_cbnz

ARM_dsb = _ida_allins.ARM_dsb

ARM_dmb = _ida_allins.ARM_dmb

ARM_isb = _ida_allins.ARM_isb

ARM_dbg = _ida_allins.ARM_dbg

ARM_und = _ida_allins.ARM_und

ARM_rrx = _ida_allins.ARM_rrx

ARM_enterx = _ida_allins.ARM_enterx

ARM_leavex = _ida_allins.ARM_leavex

ARM_chka = _ida_allins.ARM_chka

ARM_hb = _ida_allins.ARM_hb

ARM_hbl = _ida_allins.ARM_hbl

ARM_hblp = _ida_allins.ARM_hblp

ARM_hbp = _ida_allins.ARM_hbp

ARM_vaba = _ida_allins.ARM_vaba

ARM_vabal = _ida_allins.ARM_vabal

ARM_vabd = _ida_allins.ARM_vabd

ARM_vabdl = _ida_allins.ARM_vabdl

ARM_vabs = _ida_allins.ARM_vabs

ARM_vacge = _ida_allins.ARM_vacge

ARM_vacgt = _ida_allins.ARM_vacgt

ARM_vacle = _ida_allins.ARM_vacle

ARM_vaclt = _ida_allins.ARM_vaclt

ARM_vadd = _ida_allins.ARM_vadd

ARM_vaddhn = _ida_allins.ARM_vaddhn

ARM_vaddl = _ida_allins.ARM_vaddl

ARM_vaddw = _ida_allins.ARM_vaddw

ARM_vand = _ida_allins.ARM_vand

ARM_vbic = _ida_allins.ARM_vbic

ARM_vbif = _ida_allins.ARM_vbif

ARM_vbit = _ida_allins.ARM_vbit

ARM_vbsl = _ida_allins.ARM_vbsl

ARM_vceq = _ida_allins.ARM_vceq

ARM_vcge = _ida_allins.ARM_vcge

ARM_vcgt = _ida_allins.ARM_vcgt

ARM_vcle = _ida_allins.ARM_vcle

ARM_vcls = _ida_allins.ARM_vcls

ARM_vclt = _ida_allins.ARM_vclt

ARM_vclz = _ida_allins.ARM_vclz

ARM_vcmp = _ida_allins.ARM_vcmp

ARM_vcmpe = _ida_allins.ARM_vcmpe

ARM_vcnt = _ida_allins.ARM_vcnt

ARM_vcvt = _ida_allins.ARM_vcvt

ARM_vcvtr = _ida_allins.ARM_vcvtr

ARM_vcvtb = _ida_allins.ARM_vcvtb

ARM_vcvtt = _ida_allins.ARM_vcvtt

ARM_vdiv = _ida_allins.ARM_vdiv

ARM_vdup = _ida_allins.ARM_vdup

ARM_veor = _ida_allins.ARM_veor

ARM_vext = _ida_allins.ARM_vext

ARM_vfma = _ida_allins.ARM_vfma

ARM_vfms = _ida_allins.ARM_vfms

ARM_vfnma = _ida_allins.ARM_vfnma

ARM_vfnms = _ida_allins.ARM_vfnms

ARM_vhadd = _ida_allins.ARM_vhadd

ARM_vhsub = _ida_allins.ARM_vhsub

ARM_vld1 = _ida_allins.ARM_vld1

ARM_vld2 = _ida_allins.ARM_vld2

ARM_vld3 = _ida_allins.ARM_vld3

ARM_vld4 = _ida_allins.ARM_vld4

ARM_vldm = _ida_allins.ARM_vldm

ARM_vldr = _ida_allins.ARM_vldr

ARM_vmax = _ida_allins.ARM_vmax

ARM_vmin = _ida_allins.ARM_vmin

ARM_vmla = _ida_allins.ARM_vmla

ARM_vmlal = _ida_allins.ARM_vmlal

ARM_vmls = _ida_allins.ARM_vmls

ARM_vmlsl = _ida_allins.ARM_vmlsl

ARM_vmov = _ida_allins.ARM_vmov

ARM_vmovl = _ida_allins.ARM_vmovl

ARM_vmovn = _ida_allins.ARM_vmovn

ARM_vmrs = _ida_allins.ARM_vmrs

ARM_vmsr = _ida_allins.ARM_vmsr

ARM_vmul = _ida_allins.ARM_vmul

ARM_vmull = _ida_allins.ARM_vmull

ARM_vmvn = _ida_allins.ARM_vmvn

ARM_vneg = _ida_allins.ARM_vneg

ARM_vnmla = _ida_allins.ARM_vnmla

ARM_vnmls = _ida_allins.ARM_vnmls

ARM_vnmul = _ida_allins.ARM_vnmul

ARM_vorn = _ida_allins.ARM_vorn

ARM_vorr = _ida_allins.ARM_vorr

ARM_vpadal = _ida_allins.ARM_vpadal

ARM_vpadd = _ida_allins.ARM_vpadd

ARM_vpaddl = _ida_allins.ARM_vpaddl

ARM_vpmax = _ida_allins.ARM_vpmax

ARM_vpmin = _ida_allins.ARM_vpmin

ARM_vpop = _ida_allins.ARM_vpop

ARM_vpush = _ida_allins.ARM_vpush

ARM_vqabs = _ida_allins.ARM_vqabs

ARM_vqadd = _ida_allins.ARM_vqadd

ARM_vqdmlal = _ida_allins.ARM_vqdmlal

ARM_vqdmlsl = _ida_allins.ARM_vqdmlsl

ARM_vqdmulh = _ida_allins.ARM_vqdmulh

ARM_vqdmull = _ida_allins.ARM_vqdmull

ARM_vqmovn = _ida_allins.ARM_vqmovn

ARM_vqmovun = _ida_allins.ARM_vqmovun

ARM_vqneg = _ida_allins.ARM_vqneg

ARM_vqrdmulh = _ida_allins.ARM_vqrdmulh

ARM_vqrshl = _ida_allins.ARM_vqrshl

ARM_vqrshrn = _ida_allins.ARM_vqrshrn

ARM_vqrshrun = _ida_allins.ARM_vqrshrun

ARM_vqshl = _ida_allins.ARM_vqshl

ARM_vqshlu = _ida_allins.ARM_vqshlu

ARM_vqshrn = _ida_allins.ARM_vqshrn

ARM_vqshrun = _ida_allins.ARM_vqshrun

ARM_vqsub = _ida_allins.ARM_vqsub

ARM_vraddhn = _ida_allins.ARM_vraddhn

ARM_vrecpe = _ida_allins.ARM_vrecpe

ARM_vrecps = _ida_allins.ARM_vrecps

ARM_vrev16 = _ida_allins.ARM_vrev16

ARM_vrev32 = _ida_allins.ARM_vrev32

ARM_vrev64 = _ida_allins.ARM_vrev64

ARM_vrhadd = _ida_allins.ARM_vrhadd

ARM_vrshl = _ida_allins.ARM_vrshl

ARM_vrshr = _ida_allins.ARM_vrshr

ARM_vrshrn = _ida_allins.ARM_vrshrn

ARM_vrsqrte = _ida_allins.ARM_vrsqrte

ARM_vrsqrts = _ida_allins.ARM_vrsqrts

ARM_vrsra = _ida_allins.ARM_vrsra

ARM_vrsubhn = _ida_allins.ARM_vrsubhn

ARM_vshl = _ida_allins.ARM_vshl

ARM_vshll = _ida_allins.ARM_vshll

ARM_vshr = _ida_allins.ARM_vshr

ARM_vshrn = _ida_allins.ARM_vshrn

ARM_vsli = _ida_allins.ARM_vsli

ARM_vsqrt = _ida_allins.ARM_vsqrt

ARM_vsra = _ida_allins.ARM_vsra

ARM_vsri = _ida_allins.ARM_vsri

ARM_vst1 = _ida_allins.ARM_vst1

ARM_vst2 = _ida_allins.ARM_vst2

ARM_vst3 = _ida_allins.ARM_vst3

ARM_vst4 = _ida_allins.ARM_vst4

ARM_vstm = _ida_allins.ARM_vstm

ARM_vstr = _ida_allins.ARM_vstr

ARM_vsub = _ida_allins.ARM_vsub

ARM_vsubhn = _ida_allins.ARM_vsubhn

ARM_vsubl = _ida_allins.ARM_vsubl

ARM_vsubw = _ida_allins.ARM_vsubw

ARM_vswp = _ida_allins.ARM_vswp

ARM_vtbl = _ida_allins.ARM_vtbl

ARM_vtbx = _ida_allins.ARM_vtbx

ARM_vtrn = _ida_allins.ARM_vtrn

ARM_vtst = _ida_allins.ARM_vtst

ARM_vuzp = _ida_allins.ARM_vuzp

ARM_vzip = _ida_allins.ARM_vzip

ARM_eret = _ida_allins.ARM_eret

ARM_hvc = _ida_allins.ARM_hvc

ARM_lda = _ida_allins.ARM_lda

ARM_stl = _ida_allins.ARM_stl

ARM_ldaex = _ida_allins.ARM_ldaex

ARM_stlex = _ida_allins.ARM_stlex

ARM_vsel = _ida_allins.ARM_vsel

ARM_vmaxnm = _ida_allins.ARM_vmaxnm

ARM_vminnm = _ida_allins.ARM_vminnm

ARM_vcvta = _ida_allins.ARM_vcvta

ARM_vcvtn = _ida_allins.ARM_vcvtn

ARM_vcvtp = _ida_allins.ARM_vcvtp

ARM_vcvtm = _ida_allins.ARM_vcvtm

ARM_vrintx = _ida_allins.ARM_vrintx

ARM_vrintr = _ida_allins.ARM_vrintr

ARM_vrintz = _ida_allins.ARM_vrintz

ARM_vrinta = _ida_allins.ARM_vrinta

ARM_vrintn = _ida_allins.ARM_vrintn

ARM_vrintp = _ida_allins.ARM_vrintp

ARM_vrintm = _ida_allins.ARM_vrintm

ARM_aesd = _ida_allins.ARM_aesd

ARM_aese = _ida_allins.ARM_aese

ARM_aesimc = _ida_allins.ARM_aesimc

ARM_aesmc = _ida_allins.ARM_aesmc

ARM_sha1c = _ida_allins.ARM_sha1c

ARM_sha1m = _ida_allins.ARM_sha1m

ARM_sha1p = _ida_allins.ARM_sha1p

ARM_sha1h = _ida_allins.ARM_sha1h

ARM_sha1su0 = _ida_allins.ARM_sha1su0

ARM_sha1su1 = _ida_allins.ARM_sha1su1

ARM_sha256h = _ida_allins.ARM_sha256h

ARM_sha256h2 = _ida_allins.ARM_sha256h2

ARM_sha256su0 = _ida_allins.ARM_sha256su0

ARM_sha256su1 = _ida_allins.ARM_sha256su1

ARM_dcps1 = _ida_allins.ARM_dcps1

ARM_dcps2 = _ida_allins.ARM_dcps2

ARM_dcps3 = _ida_allins.ARM_dcps3

ARM_hlt = _ida_allins.ARM_hlt

ARM_sevl = _ida_allins.ARM_sevl

ARM_tbz = _ida_allins.ARM_tbz

ARM_tbnz = _ida_allins.ARM_tbnz

ARM_br = _ida_allins.ARM_br

ARM_blr = _ida_allins.ARM_blr

ARM_ldur = _ida_allins.ARM_ldur

ARM_stur = _ida_allins.ARM_stur

ARM_ldp = _ida_allins.ARM_ldp

ARM_stp = _ida_allins.ARM_stp

ARM_ldnp = _ida_allins.ARM_ldnp

ARM_stnp = _ida_allins.ARM_stnp

ARM_ldtr = _ida_allins.ARM_ldtr

ARM_sttr = _ida_allins.ARM_sttr

ARM_ldxr = _ida_allins.ARM_ldxr

ARM_stxr = _ida_allins.ARM_stxr

ARM_ldxp = _ida_allins.ARM_ldxp

ARM_stxp = _ida_allins.ARM_stxp

ARM_ldar = _ida_allins.ARM_ldar

ARM_stlr = _ida_allins.ARM_stlr

ARM_ldaxr = _ida_allins.ARM_ldaxr

ARM_stlxr = _ida_allins.ARM_stlxr

ARM_ldaxp = _ida_allins.ARM_ldaxp

ARM_stlxp = _ida_allins.ARM_stlxp

ARM_prfm = _ida_allins.ARM_prfm

ARM_prfum = _ida_allins.ARM_prfum

ARM_movi = _ida_allins.ARM_movi

ARM_mvni = _ida_allins.ARM_mvni

ARM_movz = _ida_allins.ARM_movz

ARM_movn = _ida_allins.ARM_movn

ARM_movk = _ida_allins.ARM_movk

ARM_adrp = _ida_allins.ARM_adrp

ARM_bfm = _ida_allins.ARM_bfm

ARM_sbfm = _ida_allins.ARM_sbfm

ARM_ubfm = _ida_allins.ARM_ubfm

ARM_bfxil = _ida_allins.ARM_bfxil

ARM_sbfiz = _ida_allins.ARM_sbfiz

ARM_ubfiz = _ida_allins.ARM_ubfiz

ARM_extr = _ida_allins.ARM_extr

ARM_sxtw = _ida_allins.ARM_sxtw

ARM_uxtw = _ida_allins.ARM_uxtw

ARM_eon = _ida_allins.ARM_eon

ARM_not = _ida_allins.ARM_not

ARM_cls = _ida_allins.ARM_cls

ARM_rev32 = _ida_allins.ARM_rev32

ARM_csel = _ida_allins.ARM_csel

ARM_csinc = _ida_allins.ARM_csinc

ARM_csinv = _ida_allins.ARM_csinv

ARM_csneg = _ida_allins.ARM_csneg

ARM_cset = _ida_allins.ARM_cset

ARM_csetm = _ida_allins.ARM_csetm

ARM_cinc = _ida_allins.ARM_cinc

ARM_cinv = _ida_allins.ARM_cinv

ARM_cneg = _ida_allins.ARM_cneg

ARM_ngc = _ida_allins.ARM_ngc

ARM_ccmn = _ida_allins.ARM_ccmn

ARM_ccmp = _ida_allins.ARM_ccmp

ARM_madd = _ida_allins.ARM_madd

ARM_msub = _ida_allins.ARM_msub

ARM_mneg = _ida_allins.ARM_mneg

ARM_smaddl = _ida_allins.ARM_smaddl

ARM_smsubl = _ida_allins.ARM_smsubl

ARM_smnegl = _ida_allins.ARM_smnegl

ARM_smulh = _ida_allins.ARM_smulh

ARM_umaddl = _ida_allins.ARM_umaddl

ARM_umsubl = _ida_allins.ARM_umsubl

ARM_umnegl = _ida_allins.ARM_umnegl

ARM_umulh = _ida_allins.ARM_umulh

ARM_drps = _ida_allins.ARM_drps

ARM_sys = _ida_allins.ARM_sys

ARM_sysl = _ida_allins.ARM_sysl

ARM_ic = _ida_allins.ARM_ic

ARM_dc = _ida_allins.ARM_dc

ARM_at = _ida_allins.ARM_at

ARM_tlbi = _ida_allins.ARM_tlbi

ARM_hint = _ida_allins.ARM_hint

ARM_brk = _ida_allins.ARM_brk

ARM_uaba = _ida_allins.ARM_uaba

ARM_saba = _ida_allins.ARM_saba

ARM_uabal = _ida_allins.ARM_uabal

ARM_uabal2 = _ida_allins.ARM_uabal2

ARM_sabal = _ida_allins.ARM_sabal

ARM_sabal2 = _ida_allins.ARM_sabal2

ARM_uabd = _ida_allins.ARM_uabd

ARM_sabd = _ida_allins.ARM_sabd

ARM_fabd = _ida_allins.ARM_fabd

ARM_uabdl = _ida_allins.ARM_uabdl

ARM_uabdl2 = _ida_allins.ARM_uabdl2

ARM_sabdl = _ida_allins.ARM_sabdl

ARM_sabdl2 = _ida_allins.ARM_sabdl2

ARM_abs = _ida_allins.ARM_abs

ARM_fabs = _ida_allins.ARM_fabs

ARM_facge = _ida_allins.ARM_facge

ARM_facgt = _ida_allins.ARM_facgt

ARM_facle = _ida_allins.ARM_facle

ARM_faclt = _ida_allins.ARM_faclt

ARM_fadd = _ida_allins.ARM_fadd

ARM_addhn = _ida_allins.ARM_addhn

ARM_addhn2 = _ida_allins.ARM_addhn2

ARM_uaddl = _ida_allins.ARM_uaddl

ARM_uaddl2 = _ida_allins.ARM_uaddl2

ARM_saddl = _ida_allins.ARM_saddl

ARM_saddl2 = _ida_allins.ARM_saddl2

ARM_uaddw = _ida_allins.ARM_uaddw

ARM_uaddw2 = _ida_allins.ARM_uaddw2

ARM_saddw = _ida_allins.ARM_saddw

ARM_saddw2 = _ida_allins.ARM_saddw2

ARM_bif = _ida_allins.ARM_bif

ARM_bit = _ida_allins.ARM_bit

ARM_bsl = _ida_allins.ARM_bsl

ARM_cmeq = _ida_allins.ARM_cmeq

ARM_fcmeq = _ida_allins.ARM_fcmeq

ARM_cmhs = _ida_allins.ARM_cmhs

ARM_cmge = _ida_allins.ARM_cmge

ARM_fcmge = _ida_allins.ARM_fcmge

ARM_cmhi = _ida_allins.ARM_cmhi

ARM_cmgt = _ida_allins.ARM_cmgt

ARM_fcmgt = _ida_allins.ARM_fcmgt

ARM_cmls = _ida_allins.ARM_cmls

ARM_cmle = _ida_allins.ARM_cmle

ARM_fcmle = _ida_allins.ARM_fcmle

ARM_cmlo = _ida_allins.ARM_cmlo

ARM_cmlt = _ida_allins.ARM_cmlt

ARM_fcmlt = _ida_allins.ARM_fcmlt

ARM_fcmp = _ida_allins.ARM_fcmp

ARM_fcmpe = _ida_allins.ARM_fcmpe

ARM_fccmp = _ida_allins.ARM_fccmp

ARM_fccmpe = _ida_allins.ARM_fccmpe

ARM_fcsel = _ida_allins.ARM_fcsel

ARM_cnt = _ida_allins.ARM_cnt

ARM_fcvt = _ida_allins.ARM_fcvt

ARM_fcvtzs = _ida_allins.ARM_fcvtzs

ARM_fcvtas = _ida_allins.ARM_fcvtas

ARM_fcvtns = _ida_allins.ARM_fcvtns

ARM_fcvtps = _ida_allins.ARM_fcvtps

ARM_fcvtms = _ida_allins.ARM_fcvtms

ARM_fcvtzu = _ida_allins.ARM_fcvtzu

ARM_fcvtau = _ida_allins.ARM_fcvtau

ARM_fcvtnu = _ida_allins.ARM_fcvtnu

ARM_fcvtpu = _ida_allins.ARM_fcvtpu

ARM_fcvtmu = _ida_allins.ARM_fcvtmu

ARM_ucvtf = _ida_allins.ARM_ucvtf

ARM_scvtf = _ida_allins.ARM_scvtf

ARM_fcvtn = _ida_allins.ARM_fcvtn

ARM_fcvtn2 = _ida_allins.ARM_fcvtn2

ARM_fcvtl = _ida_allins.ARM_fcvtl

ARM_fcvtl2 = _ida_allins.ARM_fcvtl2

ARM_fcvtxn = _ida_allins.ARM_fcvtxn

ARM_fcvtxn2 = _ida_allins.ARM_fcvtxn2

ARM_frinta = _ida_allins.ARM_frinta

ARM_frinti = _ida_allins.ARM_frinti

ARM_frintm = _ida_allins.ARM_frintm

ARM_frintn = _ida_allins.ARM_frintn

ARM_frintp = _ida_allins.ARM_frintp

ARM_frintx = _ida_allins.ARM_frintx

ARM_frintz = _ida_allins.ARM_frintz

ARM_fmadd = _ida_allins.ARM_fmadd

ARM_fmsub = _ida_allins.ARM_fmsub

ARM_fnmadd = _ida_allins.ARM_fnmadd

ARM_fnmsub = _ida_allins.ARM_fnmsub

ARM_fdiv = _ida_allins.ARM_fdiv

ARM_dup = _ida_allins.ARM_dup

ARM_ins = _ida_allins.ARM_ins

ARM_ext = _ida_allins.ARM_ext

ARM_uhadd = _ida_allins.ARM_uhadd

ARM_shadd = _ida_allins.ARM_shadd

ARM_uhsub = _ida_allins.ARM_uhsub

ARM_shsub = _ida_allins.ARM_shsub

ARM_ld1 = _ida_allins.ARM_ld1

ARM_ld2 = _ida_allins.ARM_ld2

ARM_ld3 = _ida_allins.ARM_ld3

ARM_ld4 = _ida_allins.ARM_ld4

ARM_ld1r = _ida_allins.ARM_ld1r

ARM_ld2r = _ida_allins.ARM_ld2r

ARM_ld3r = _ida_allins.ARM_ld3r

ARM_ld4r = _ida_allins.ARM_ld4r

ARM_umax = _ida_allins.ARM_umax

ARM_smax = _ida_allins.ARM_smax

ARM_fmax = _ida_allins.ARM_fmax

ARM_fmaxnm = _ida_allins.ARM_fmaxnm

ARM_umin = _ida_allins.ARM_umin

ARM_smin = _ida_allins.ARM_smin

ARM_fmin = _ida_allins.ARM_fmin

ARM_fminnm = _ida_allins.ARM_fminnm

ARM_fmla = _ida_allins.ARM_fmla

ARM_umlal2 = _ida_allins.ARM_umlal2

ARM_smlal2 = _ida_allins.ARM_smlal2

ARM_fmls = _ida_allins.ARM_fmls

ARM_umlsl = _ida_allins.ARM_umlsl

ARM_umlsl2 = _ida_allins.ARM_umlsl2

ARM_smlsl = _ida_allins.ARM_smlsl

ARM_smlsl2 = _ida_allins.ARM_smlsl2

ARM_umov = _ida_allins.ARM_umov

ARM_smov = _ida_allins.ARM_smov

ARM_fmov = _ida_allins.ARM_fmov

ARM_uxtl = _ida_allins.ARM_uxtl

ARM_uxtl2 = _ida_allins.ARM_uxtl2

ARM_sxtl = _ida_allins.ARM_sxtl

ARM_sxtl2 = _ida_allins.ARM_sxtl2

ARM_xtn = _ida_allins.ARM_xtn

ARM_xtn2 = _ida_allins.ARM_xtn2

ARM_fmul = _ida_allins.ARM_fmul

ARM_pmul = _ida_allins.ARM_pmul

ARM_fmulx = _ida_allins.ARM_fmulx

ARM_fnmul = _ida_allins.ARM_fnmul

ARM_umull2 = _ida_allins.ARM_umull2

ARM_smull2 = _ida_allins.ARM_smull2

ARM_pmull = _ida_allins.ARM_pmull

ARM_pmull2 = _ida_allins.ARM_pmull2

ARM_fneg = _ida_allins.ARM_fneg

ARM_uadalp = _ida_allins.ARM_uadalp

ARM_sadalp = _ida_allins.ARM_sadalp

ARM_addp = _ida_allins.ARM_addp

ARM_faddp = _ida_allins.ARM_faddp

ARM_uaddlp = _ida_allins.ARM_uaddlp

ARM_saddlp = _ida_allins.ARM_saddlp

ARM_umaxp = _ida_allins.ARM_umaxp

ARM_smaxp = _ida_allins.ARM_smaxp

ARM_fmaxp = _ida_allins.ARM_fmaxp

ARM_fmaxnmp = _ida_allins.ARM_fmaxnmp

ARM_uminp = _ida_allins.ARM_uminp

ARM_sminp = _ida_allins.ARM_sminp

ARM_fminp = _ida_allins.ARM_fminp

ARM_fminnmp = _ida_allins.ARM_fminnmp

ARM_sqabs = _ida_allins.ARM_sqabs

ARM_uqadd = _ida_allins.ARM_uqadd

ARM_sqadd = _ida_allins.ARM_sqadd

ARM_suqadd = _ida_allins.ARM_suqadd

ARM_usqadd = _ida_allins.ARM_usqadd

ARM_sqdmlal = _ida_allins.ARM_sqdmlal

ARM_sqdmlal2 = _ida_allins.ARM_sqdmlal2

ARM_sqdmlsl = _ida_allins.ARM_sqdmlsl

ARM_sqdmlsl2 = _ida_allins.ARM_sqdmlsl2

ARM_sqdmulh = _ida_allins.ARM_sqdmulh

ARM_sqdmull = _ida_allins.ARM_sqdmull

ARM_sqdmull2 = _ida_allins.ARM_sqdmull2

ARM_uqxtn = _ida_allins.ARM_uqxtn

ARM_uqxtn2 = _ida_allins.ARM_uqxtn2

ARM_sqxtn = _ida_allins.ARM_sqxtn

ARM_sqxtn2 = _ida_allins.ARM_sqxtn2

ARM_sqxtun = _ida_allins.ARM_sqxtun

ARM_sqxtun2 = _ida_allins.ARM_sqxtun2

ARM_sqneg = _ida_allins.ARM_sqneg

ARM_sqrdmulh = _ida_allins.ARM_sqrdmulh

ARM_uqrshl = _ida_allins.ARM_uqrshl

ARM_sqrshl = _ida_allins.ARM_sqrshl

ARM_uqrshrn = _ida_allins.ARM_uqrshrn

ARM_uqrshrn2 = _ida_allins.ARM_uqrshrn2

ARM_sqrshrn = _ida_allins.ARM_sqrshrn

ARM_sqrshrn2 = _ida_allins.ARM_sqrshrn2

ARM_sqrshrun = _ida_allins.ARM_sqrshrun

ARM_sqrshrun2 = _ida_allins.ARM_sqrshrun2

ARM_uqshl = _ida_allins.ARM_uqshl

ARM_sqshl = _ida_allins.ARM_sqshl

ARM_sqshlu = _ida_allins.ARM_sqshlu

ARM_uqshrn = _ida_allins.ARM_uqshrn

ARM_uqshrn2 = _ida_allins.ARM_uqshrn2

ARM_sqshrn = _ida_allins.ARM_sqshrn

ARM_sqshrn2 = _ida_allins.ARM_sqshrn2

ARM_sqshrun = _ida_allins.ARM_sqshrun

ARM_sqshrun2 = _ida_allins.ARM_sqshrun2

ARM_uqsub = _ida_allins.ARM_uqsub

ARM_sqsub = _ida_allins.ARM_sqsub

ARM_raddhn = _ida_allins.ARM_raddhn

ARM_raddhn2 = _ida_allins.ARM_raddhn2

ARM_urecpe = _ida_allins.ARM_urecpe

ARM_frecpe = _ida_allins.ARM_frecpe

ARM_frecps = _ida_allins.ARM_frecps

ARM_frecpx = _ida_allins.ARM_frecpx

ARM_rev64 = _ida_allins.ARM_rev64

ARM_urhadd = _ida_allins.ARM_urhadd

ARM_srhadd = _ida_allins.ARM_srhadd

ARM_urshl = _ida_allins.ARM_urshl

ARM_srshl = _ida_allins.ARM_srshl

ARM_urshr = _ida_allins.ARM_urshr

ARM_srshr = _ida_allins.ARM_srshr

ARM_rshrn = _ida_allins.ARM_rshrn

ARM_rshrn2 = _ida_allins.ARM_rshrn2

ARM_ursqrte = _ida_allins.ARM_ursqrte

ARM_frsqrte = _ida_allins.ARM_frsqrte

ARM_frsqrts = _ida_allins.ARM_frsqrts

ARM_ursra = _ida_allins.ARM_ursra

ARM_srsra = _ida_allins.ARM_srsra

ARM_rsubhn = _ida_allins.ARM_rsubhn

ARM_rsubhn2 = _ida_allins.ARM_rsubhn2

ARM_ushl = _ida_allins.ARM_ushl

ARM_sshl = _ida_allins.ARM_sshl

ARM_ushll = _ida_allins.ARM_ushll

ARM_ushll2 = _ida_allins.ARM_ushll2

ARM_sshll = _ida_allins.ARM_sshll

ARM_sshll2 = _ida_allins.ARM_sshll2

ARM_ushr = _ida_allins.ARM_ushr

ARM_sshr = _ida_allins.ARM_sshr

ARM_shrn = _ida_allins.ARM_shrn

ARM_shrn2 = _ida_allins.ARM_shrn2

ARM_shl = _ida_allins.ARM_shl

ARM_shll = _ida_allins.ARM_shll

ARM_shll2 = _ida_allins.ARM_shll2

ARM_sli = _ida_allins.ARM_sli

ARM_fsqrt = _ida_allins.ARM_fsqrt

ARM_usra = _ida_allins.ARM_usra

ARM_ssra = _ida_allins.ARM_ssra

ARM_sri = _ida_allins.ARM_sri

ARM_st1 = _ida_allins.ARM_st1

ARM_st2 = _ida_allins.ARM_st2

ARM_st3 = _ida_allins.ARM_st3

ARM_st4 = _ida_allins.ARM_st4

ARM_fsub = _ida_allins.ARM_fsub

ARM_subhn = _ida_allins.ARM_subhn

ARM_subhn2 = _ida_allins.ARM_subhn2

ARM_usubl = _ida_allins.ARM_usubl

ARM_usubl2 = _ida_allins.ARM_usubl2

ARM_ssubl = _ida_allins.ARM_ssubl

ARM_ssubl2 = _ida_allins.ARM_ssubl2

ARM_usubw = _ida_allins.ARM_usubw

ARM_usubw2 = _ida_allins.ARM_usubw2

ARM_ssubw = _ida_allins.ARM_ssubw

ARM_ssubw2 = _ida_allins.ARM_ssubw2

ARM_tbl = _ida_allins.ARM_tbl

ARM_tbx = _ida_allins.ARM_tbx

ARM_trn1 = _ida_allins.ARM_trn1

ARM_trn2 = _ida_allins.ARM_trn2

ARM_cmtst = _ida_allins.ARM_cmtst

ARM_uzp1 = _ida_allins.ARM_uzp1

ARM_uzp2 = _ida_allins.ARM_uzp2

ARM_zip1 = _ida_allins.ARM_zip1

ARM_zip2 = _ida_allins.ARM_zip2

ARM_addv = _ida_allins.ARM_addv

ARM_uaddlv = _ida_allins.ARM_uaddlv

ARM_saddlv = _ida_allins.ARM_saddlv

ARM_umaxv = _ida_allins.ARM_umaxv

ARM_smaxv = _ida_allins.ARM_smaxv

ARM_fmaxv = _ida_allins.ARM_fmaxv

ARM_fmaxnmv = _ida_allins.ARM_fmaxnmv

ARM_uminv = _ida_allins.ARM_uminv

ARM_sminv = _ida_allins.ARM_sminv

ARM_fminv = _ida_allins.ARM_fminv

ARM_fminnmv = _ida_allins.ARM_fminnmv

ARM_swpl = _ida_allins.ARM_swpl

ARM_swpa = _ida_allins.ARM_swpa

ARM_swpal = _ida_allins.ARM_swpal

ARM_ldapr = _ida_allins.ARM_ldapr

ARM_ldadd = _ida_allins.ARM_ldadd

ARM_ldaddl = _ida_allins.ARM_ldaddl

ARM_ldadda = _ida_allins.ARM_ldadda

ARM_ldaddal = _ida_allins.ARM_ldaddal

ARM_stadd = _ida_allins.ARM_stadd

ARM_staddl = _ida_allins.ARM_staddl

ARM_ldclr = _ida_allins.ARM_ldclr

ARM_ldclrl = _ida_allins.ARM_ldclrl

ARM_ldclra = _ida_allins.ARM_ldclra

ARM_ldclral = _ida_allins.ARM_ldclral

ARM_stclr = _ida_allins.ARM_stclr

ARM_stclrl = _ida_allins.ARM_stclrl

ARM_ldeor = _ida_allins.ARM_ldeor

ARM_ldeorl = _ida_allins.ARM_ldeorl

ARM_ldeora = _ida_allins.ARM_ldeora

ARM_ldeoral = _ida_allins.ARM_ldeoral

ARM_steor = _ida_allins.ARM_steor

ARM_steorl = _ida_allins.ARM_steorl

ARM_ldset = _ida_allins.ARM_ldset

ARM_ldsetl = _ida_allins.ARM_ldsetl

ARM_ldseta = _ida_allins.ARM_ldseta

ARM_ldsetal = _ida_allins.ARM_ldsetal

ARM_stset = _ida_allins.ARM_stset

ARM_stsetl = _ida_allins.ARM_stsetl

ARM_ldsmax = _ida_allins.ARM_ldsmax

ARM_ldsmaxl = _ida_allins.ARM_ldsmaxl

ARM_ldsmaxa = _ida_allins.ARM_ldsmaxa

ARM_ldsmaxal = _ida_allins.ARM_ldsmaxal

ARM_stsmax = _ida_allins.ARM_stsmax

ARM_stsmaxl = _ida_allins.ARM_stsmaxl

ARM_ldsmin = _ida_allins.ARM_ldsmin

ARM_ldsminl = _ida_allins.ARM_ldsminl

ARM_ldsmina = _ida_allins.ARM_ldsmina

ARM_ldsminal = _ida_allins.ARM_ldsminal

ARM_stsmin = _ida_allins.ARM_stsmin

ARM_stsminl = _ida_allins.ARM_stsminl

ARM_ldumax = _ida_allins.ARM_ldumax

ARM_ldumaxl = _ida_allins.ARM_ldumaxl

ARM_ldumaxa = _ida_allins.ARM_ldumaxa

ARM_ldumaxal = _ida_allins.ARM_ldumaxal

ARM_stumax = _ida_allins.ARM_stumax

ARM_stumaxl = _ida_allins.ARM_stumaxl

ARM_ldumin = _ida_allins.ARM_ldumin

ARM_lduminl = _ida_allins.ARM_lduminl

ARM_ldumina = _ida_allins.ARM_ldumina

ARM_lduminal = _ida_allins.ARM_lduminal

ARM_stumin = _ida_allins.ARM_stumin

ARM_stuminl = _ida_allins.ARM_stuminl

ARM_cas = _ida_allins.ARM_cas

ARM_casl = _ida_allins.ARM_casl

ARM_casa = _ida_allins.ARM_casa

ARM_casal = _ida_allins.ARM_casal

ARM_casp = _ida_allins.ARM_casp

ARM_caspl = _ida_allins.ARM_caspl

ARM_caspa = _ida_allins.ARM_caspa

ARM_caspal = _ida_allins.ARM_caspal

ARM_ldlar = _ida_allins.ARM_ldlar

ARM_stllr = _ida_allins.ARM_stllr

ARM_sqrdmlah = _ida_allins.ARM_sqrdmlah

ARM_sqrdmlsh = _ida_allins.ARM_sqrdmlsh

ARM_pac = _ida_allins.ARM_pac

ARM_aut = _ida_allins.ARM_aut

ARM_xpac = _ida_allins.ARM_xpac

ARM_ldrd2 = _ida_allins.ARM_ldrd2

ARM_strd2 = _ida_allins.ARM_strd2

ARM_crc32 = _ida_allins.ARM_crc32

ARM_crc32c = _ida_allins.ARM_crc32c

ARM_tt = _ida_allins.ARM_tt

ARM_tta = _ida_allins.ARM_tta

ARM_sg = _ida_allins.ARM_sg

ARM_vlldm = _ida_allins.ARM_vlldm

ARM_vlstm = _ida_allins.ARM_vlstm

ARM_pldw = _ida_allins.ARM_pldw

ARM_vqrdmlah = _ida_allins.ARM_vqrdmlah

ARM_vqrdmlsh = _ida_allins.ARM_vqrdmlsh

ARM_vmovx = _ida_allins.ARM_vmovx

ARM_vins = _ida_allins.ARM_vins

ARM_vjcvt = _ida_allins.ARM_vjcvt

ARM_fjcvtzs = _ida_allins.ARM_fjcvtzs

ARM_ldapur = _ida_allins.ARM_ldapur

ARM_stlur = _ida_allins.ARM_stlur

ARM_cfinv = _ida_allins.ARM_cfinv

ARM_rmif = _ida_allins.ARM_rmif

ARM_setf8 = _ida_allins.ARM_setf8

ARM_setf16 = _ida_allins.ARM_setf16

ARM_xaflag = _ida_allins.ARM_xaflag

ARM_axflag = _ida_allins.ARM_axflag

ARM_addg = _ida_allins.ARM_addg

ARM_subg = _ida_allins.ARM_subg

ARM_subp = _ida_allins.ARM_subp

ARM_cmpp = _ida_allins.ARM_cmpp

ARM_irg = _ida_allins.ARM_irg

ARM_gmi = _ida_allins.ARM_gmi

ARM_stg = _ida_allins.ARM_stg

ARM_stzg = _ida_allins.ARM_stzg

ARM_stzgm = _ida_allins.ARM_stzgm

ARM_st2g = _ida_allins.ARM_st2g

ARM_stz2g = _ida_allins.ARM_stz2g

ARM_stgm = _ida_allins.ARM_stgm

ARM_stgp = _ida_allins.ARM_stgp

ARM_ldg = _ida_allins.ARM_ldg

ARM_ldgm = _ida_allins.ARM_ldgm

ARM_bti = _ida_allins.ARM_bti

ARM_sb = _ida_allins.ARM_sb

ARM_ssbb = _ida_allins.ARM_ssbb

ARM_pssbb = _ida_allins.ARM_pssbb

ARM_frint32x = _ida_allins.ARM_frint32x

ARM_frint32z = _ida_allins.ARM_frint32z

ARM_frint64x = _ida_allins.ARM_frint64x

ARM_frint64z = _ida_allins.ARM_frint64z

ARM_last = _ida_allins.ARM_last

TMS6_null = _ida_allins.TMS6_null

TMS6_abs = _ida_allins.TMS6_abs

TMS6_add = _ida_allins.TMS6_add

TMS6_addu = _ida_allins.TMS6_addu

TMS6_addab = _ida_allins.TMS6_addab

TMS6_addah = _ida_allins.TMS6_addah

TMS6_addaw = _ida_allins.TMS6_addaw

TMS6_addk = _ida_allins.TMS6_addk

TMS6_add2 = _ida_allins.TMS6_add2

TMS6_and = _ida_allins.TMS6_and

TMS6_b = _ida_allins.TMS6_b

TMS6_clr = _ida_allins.TMS6_clr

TMS6_cmpeq = _ida_allins.TMS6_cmpeq

TMS6_cmpgt = _ida_allins.TMS6_cmpgt

TMS6_cmpgtu = _ida_allins.TMS6_cmpgtu

TMS6_cmplt = _ida_allins.TMS6_cmplt

TMS6_cmpltu = _ida_allins.TMS6_cmpltu

TMS6_ext = _ida_allins.TMS6_ext

TMS6_extu = _ida_allins.TMS6_extu

TMS6_idle = _ida_allins.TMS6_idle

TMS6_ldb = _ida_allins.TMS6_ldb

TMS6_ldbu = _ida_allins.TMS6_ldbu

TMS6_ldh = _ida_allins.TMS6_ldh

TMS6_ldhu = _ida_allins.TMS6_ldhu

TMS6_ldw = _ida_allins.TMS6_ldw

TMS6_lmbd = _ida_allins.TMS6_lmbd

TMS6_mpy = _ida_allins.TMS6_mpy

TMS6_mpyu = _ida_allins.TMS6_mpyu

TMS6_mpyus = _ida_allins.TMS6_mpyus

TMS6_mpysu = _ida_allins.TMS6_mpysu

TMS6_mpyh = _ida_allins.TMS6_mpyh

TMS6_mpyhu = _ida_allins.TMS6_mpyhu

TMS6_mpyhus = _ida_allins.TMS6_mpyhus

TMS6_mpyhsu = _ida_allins.TMS6_mpyhsu

TMS6_mpyhl = _ida_allins.TMS6_mpyhl

TMS6_mpyhlu = _ida_allins.TMS6_mpyhlu

TMS6_mpyhuls = _ida_allins.TMS6_mpyhuls

TMS6_mpyhslu = _ida_allins.TMS6_mpyhslu

TMS6_mpylh = _ida_allins.TMS6_mpylh

TMS6_mpylhu = _ida_allins.TMS6_mpylhu

TMS6_mpyluhs = _ida_allins.TMS6_mpyluhs

TMS6_mpylshu = _ida_allins.TMS6_mpylshu

TMS6_mv = _ida_allins.TMS6_mv

TMS6_mvc = _ida_allins.TMS6_mvc

TMS6_mvk = _ida_allins.TMS6_mvk

TMS6_mvkh = _ida_allins.TMS6_mvkh

TMS6_mvklh = _ida_allins.TMS6_mvklh

TMS6_neg = _ida_allins.TMS6_neg

TMS6_nop = _ida_allins.TMS6_nop

TMS6_norm = _ida_allins.TMS6_norm

TMS6_not = _ida_allins.TMS6_not

TMS6_or = _ida_allins.TMS6_or

TMS6_sadd = _ida_allins.TMS6_sadd

TMS6_sat = _ida_allins.TMS6_sat

TMS6_set = _ida_allins.TMS6_set

TMS6_shl = _ida_allins.TMS6_shl

TMS6_shr = _ida_allins.TMS6_shr

TMS6_shru = _ida_allins.TMS6_shru

TMS6_smpy = _ida_allins.TMS6_smpy

TMS6_smpyhl = _ida_allins.TMS6_smpyhl

TMS6_smpylh = _ida_allins.TMS6_smpylh

TMS6_smpyh = _ida_allins.TMS6_smpyh

TMS6_sshl = _ida_allins.TMS6_sshl

TMS6_ssub = _ida_allins.TMS6_ssub

TMS6_stb = _ida_allins.TMS6_stb

TMS6_stbu = _ida_allins.TMS6_stbu

TMS6_sth = _ida_allins.TMS6_sth

TMS6_sthu = _ida_allins.TMS6_sthu

TMS6_stw = _ida_allins.TMS6_stw

TMS6_sub = _ida_allins.TMS6_sub

TMS6_subu = _ida_allins.TMS6_subu

TMS6_subab = _ida_allins.TMS6_subab

TMS6_subah = _ida_allins.TMS6_subah

TMS6_subaw = _ida_allins.TMS6_subaw

TMS6_subc = _ida_allins.TMS6_subc

TMS6_sub2 = _ida_allins.TMS6_sub2

TMS6_xor = _ida_allins.TMS6_xor

TMS6_zero = _ida_allins.TMS6_zero

TMS6_abs2 = _ida_allins.TMS6_abs2

TMS6_absdp = _ida_allins.TMS6_absdp

TMS6_abssp = _ida_allins.TMS6_abssp

TMS6_add4 = _ida_allins.TMS6_add4

TMS6_addad = _ida_allins.TMS6_addad

TMS6_adddp = _ida_allins.TMS6_adddp

TMS6_addkpc = _ida_allins.TMS6_addkpc

TMS6_addsp = _ida_allins.TMS6_addsp

TMS6_addsub = _ida_allins.TMS6_addsub

TMS6_addsub2 = _ida_allins.TMS6_addsub2

TMS6_andn = _ida_allins.TMS6_andn

TMS6_avg2 = _ida_allins.TMS6_avg2

TMS6_avgu4 = _ida_allins.TMS6_avgu4

TMS6_bdec = _ida_allins.TMS6_bdec

TMS6_bitc4 = _ida_allins.TMS6_bitc4

TMS6_bitr = _ida_allins.TMS6_bitr

TMS6_bnop = _ida_allins.TMS6_bnop

TMS6_bpos = _ida_allins.TMS6_bpos

TMS6_callp = _ida_allins.TMS6_callp

TMS6_cmpeq2 = _ida_allins.TMS6_cmpeq2

TMS6_cmpeq4 = _ida_allins.TMS6_cmpeq4

TMS6_cmpeqdp = _ida_allins.TMS6_cmpeqdp

TMS6_cmpeqsp = _ida_allins.TMS6_cmpeqsp

TMS6_cmpgt2 = _ida_allins.TMS6_cmpgt2

TMS6_cmpgtdp = _ida_allins.TMS6_cmpgtdp

TMS6_cmpgtsp = _ida_allins.TMS6_cmpgtsp

TMS6_cmpgtu4 = _ida_allins.TMS6_cmpgtu4

TMS6_cmplt2 = _ida_allins.TMS6_cmplt2

TMS6_cmpltdp = _ida_allins.TMS6_cmpltdp

TMS6_cmpltsp = _ida_allins.TMS6_cmpltsp

TMS6_cmpltu4 = _ida_allins.TMS6_cmpltu4

TMS6_cmpy = _ida_allins.TMS6_cmpy

TMS6_cmpyr = _ida_allins.TMS6_cmpyr

TMS6_cmpyr1 = _ida_allins.TMS6_cmpyr1

TMS6_ddotp4 = _ida_allins.TMS6_ddotp4

TMS6_ddotph2 = _ida_allins.TMS6_ddotph2

TMS6_ddotph2r = _ida_allins.TMS6_ddotph2r

TMS6_ddotpl2 = _ida_allins.TMS6_ddotpl2

TMS6_ddotpl2r = _ida_allins.TMS6_ddotpl2r

TMS6_deal = _ida_allins.TMS6_deal

TMS6_dint = _ida_allins.TMS6_dint

TMS6_dmv = _ida_allins.TMS6_dmv

TMS6_dotp2 = _ida_allins.TMS6_dotp2

TMS6_dotpn2 = _ida_allins.TMS6_dotpn2

TMS6_dotpnrsu2 = _ida_allins.TMS6_dotpnrsu2

TMS6_dotpnrus2 = _ida_allins.TMS6_dotpnrus2

TMS6_dotprsu2 = _ida_allins.TMS6_dotprsu2

TMS6_dotprus2 = _ida_allins.TMS6_dotprus2

TMS6_dotpsu4 = _ida_allins.TMS6_dotpsu4

TMS6_dotpu4 = _ida_allins.TMS6_dotpu4

TMS6_dotpus4 = _ida_allins.TMS6_dotpus4

TMS6_dpack2 = _ida_allins.TMS6_dpack2

TMS6_dpackx2 = _ida_allins.TMS6_dpackx2

TMS6_dpint = _ida_allins.TMS6_dpint

TMS6_dpsp = _ida_allins.TMS6_dpsp

TMS6_dptrunc = _ida_allins.TMS6_dptrunc

TMS6_gmpy = _ida_allins.TMS6_gmpy

TMS6_gmpy4 = _ida_allins.TMS6_gmpy4

TMS6_intdp = _ida_allins.TMS6_intdp

TMS6_intdpu = _ida_allins.TMS6_intdpu

TMS6_intsp = _ida_allins.TMS6_intsp

TMS6_intspu = _ida_allins.TMS6_intspu

TMS6_lddw = _ida_allins.TMS6_lddw

TMS6_ldndw = _ida_allins.TMS6_ldndw

TMS6_ldnw = _ida_allins.TMS6_ldnw

TMS6_max2 = _ida_allins.TMS6_max2

TMS6_maxu4 = _ida_allins.TMS6_maxu4

TMS6_min2 = _ida_allins.TMS6_min2

TMS6_minu4 = _ida_allins.TMS6_minu4

TMS6_mpy2 = _ida_allins.TMS6_mpy2

TMS6_mpy2ir = _ida_allins.TMS6_mpy2ir

TMS6_mpy32 = _ida_allins.TMS6_mpy32

TMS6_mpy32su = _ida_allins.TMS6_mpy32su

TMS6_mpy32u = _ida_allins.TMS6_mpy32u

TMS6_mpy32us = _ida_allins.TMS6_mpy32us

TMS6_mpydp = _ida_allins.TMS6_mpydp

TMS6_mpyhi = _ida_allins.TMS6_mpyhi

TMS6_mpyhir = _ida_allins.TMS6_mpyhir

TMS6_mpyi = _ida_allins.TMS6_mpyi

TMS6_mpyid = _ida_allins.TMS6_mpyid

TMS6_mpyih = _ida_allins.TMS6_mpyih

TMS6_mpyihr = _ida_allins.TMS6_mpyihr

TMS6_mpyil = _ida_allins.TMS6_mpyil

TMS6_mpyilr = _ida_allins.TMS6_mpyilr

TMS6_mpyli = _ida_allins.TMS6_mpyli

TMS6_mpylir = _ida_allins.TMS6_mpylir

TMS6_mpysp = _ida_allins.TMS6_mpysp

TMS6_mpysp2dp = _ida_allins.TMS6_mpysp2dp

TMS6_mpyspdp = _ida_allins.TMS6_mpyspdp

TMS6_mpysu4 = _ida_allins.TMS6_mpysu4

TMS6_mpyu4 = _ida_allins.TMS6_mpyu4

TMS6_mpyus4 = _ida_allins.TMS6_mpyus4

TMS6_mvd = _ida_allins.TMS6_mvd

TMS6_mvkl = _ida_allins.TMS6_mvkl

TMS6_pack2 = _ida_allins.TMS6_pack2

TMS6_packh2 = _ida_allins.TMS6_packh2

TMS6_packh4 = _ida_allins.TMS6_packh4

TMS6_packhl2 = _ida_allins.TMS6_packhl2

TMS6_packl4 = _ida_allins.TMS6_packl4

TMS6_packlh2 = _ida_allins.TMS6_packlh2

TMS6_rcpdp = _ida_allins.TMS6_rcpdp

TMS6_rcpsp = _ida_allins.TMS6_rcpsp

TMS6_rint = _ida_allins.TMS6_rint

TMS6_rotl = _ida_allins.TMS6_rotl

TMS6_rpack2 = _ida_allins.TMS6_rpack2

TMS6_rsqrdp = _ida_allins.TMS6_rsqrdp

TMS6_rsqrsp = _ida_allins.TMS6_rsqrsp

TMS6_sadd2 = _ida_allins.TMS6_sadd2

TMS6_saddsu2 = _ida_allins.TMS6_saddsu2

TMS6_saddsub = _ida_allins.TMS6_saddsub

TMS6_saddsub2 = _ida_allins.TMS6_saddsub2

TMS6_saddu4 = _ida_allins.TMS6_saddu4

TMS6_saddus2 = _ida_allins.TMS6_saddus2

TMS6_shfl = _ida_allins.TMS6_shfl

TMS6_shfl3 = _ida_allins.TMS6_shfl3

TMS6_shlmb = _ida_allins.TMS6_shlmb

TMS6_shr2 = _ida_allins.TMS6_shr2

TMS6_shrmb = _ida_allins.TMS6_shrmb

TMS6_shru2 = _ida_allins.TMS6_shru2

TMS6_smpy2 = _ida_allins.TMS6_smpy2

TMS6_smpy32 = _ida_allins.TMS6_smpy32

TMS6_spack2 = _ida_allins.TMS6_spack2

TMS6_spacku4 = _ida_allins.TMS6_spacku4

TMS6_spdp = _ida_allins.TMS6_spdp

TMS6_spint = _ida_allins.TMS6_spint

TMS6_spkernel = _ida_allins.TMS6_spkernel

TMS6_spkernelr = _ida_allins.TMS6_spkernelr

TMS6_sploop = _ida_allins.TMS6_sploop

TMS6_sploopd = _ida_allins.TMS6_sploopd

TMS6_sploopw = _ida_allins.TMS6_sploopw

TMS6_spmask = _ida_allins.TMS6_spmask

TMS6_spmaskr = _ida_allins.TMS6_spmaskr

TMS6_sptrunc = _ida_allins.TMS6_sptrunc

TMS6_sshvl = _ida_allins.TMS6_sshvl

TMS6_sshvr = _ida_allins.TMS6_sshvr

TMS6_ssub2 = _ida_allins.TMS6_ssub2

TMS6_stdw = _ida_allins.TMS6_stdw

TMS6_stndw = _ida_allins.TMS6_stndw

TMS6_stnw = _ida_allins.TMS6_stnw

TMS6_sub4 = _ida_allins.TMS6_sub4

TMS6_subabs4 = _ida_allins.TMS6_subabs4

TMS6_subdp = _ida_allins.TMS6_subdp

TMS6_subsp = _ida_allins.TMS6_subsp

TMS6_swap2 = _ida_allins.TMS6_swap2

TMS6_swap4 = _ida_allins.TMS6_swap4

TMS6_swe = _ida_allins.TMS6_swe

TMS6_swenr = _ida_allins.TMS6_swenr

TMS6_unpkhu4 = _ida_allins.TMS6_unpkhu4

TMS6_unpklu4 = _ida_allins.TMS6_unpklu4

TMS6_xormpy = _ida_allins.TMS6_xormpy

TMS6_xpnd2 = _ida_allins.TMS6_xpnd2

TMS6_xpnd4 = _ida_allins.TMS6_xpnd4

TMS6_last = _ida_allins.TMS6_last

I196_null = _ida_allins.I196_null

I196_add2 = _ida_allins.I196_add2

I196_add3 = _ida_allins.I196_add3

I196_addb2 = _ida_allins.I196_addb2

I196_addb3 = _ida_allins.I196_addb3

I196_addc = _ida_allins.I196_addc

I196_addcb = _ida_allins.I196_addcb

I196_and2 = _ida_allins.I196_and2

I196_and3 = _ida_allins.I196_and3

I196_andb2 = _ida_allins.I196_andb2

I196_andb3 = _ida_allins.I196_andb3

I196_bmov = _ida_allins.I196_bmov

I196_bmovi = _ida_allins.I196_bmovi

I196_br = _ida_allins.I196_br

I196_clr = _ida_allins.I196_clr

I196_clrb = _ida_allins.I196_clrb

I196_clrc = _ida_allins.I196_clrc

I196_clrvt = _ida_allins.I196_clrvt

I196_cmp = _ida_allins.I196_cmp

I196_cmpb = _ida_allins.I196_cmpb

I196_cmpl = _ida_allins.I196_cmpl

I196_dec = _ida_allins.I196_dec

I196_decb = _ida_allins.I196_decb

I196_di = _ida_allins.I196_di

I196_div = _ida_allins.I196_div

I196_divb = _ida_allins.I196_divb

I196_divu = _ida_allins.I196_divu

I196_divub = _ida_allins.I196_divub

I196_djnz = _ida_allins.I196_djnz

I196_djnzw = _ida_allins.I196_djnzw

I196_dpts = _ida_allins.I196_dpts

I196_ei = _ida_allins.I196_ei

I196_epts = _ida_allins.I196_epts

I196_ext = _ida_allins.I196_ext

I196_extb = _ida_allins.I196_extb

I196_idlpd = _ida_allins.I196_idlpd

I196_inc = _ida_allins.I196_inc

I196_incb = _ida_allins.I196_incb

I196_jbc = _ida_allins.I196_jbc

I196_jbs = _ida_allins.I196_jbs

I196_jc = _ida_allins.I196_jc

I196_je = _ida_allins.I196_je

I196_jge = _ida_allins.I196_jge

I196_jgt = _ida_allins.I196_jgt

I196_jh = _ida_allins.I196_jh

I196_jle = _ida_allins.I196_jle

I196_jlt = _ida_allins.I196_jlt

I196_jnc = _ida_allins.I196_jnc

I196_jne = _ida_allins.I196_jne

I196_jnh = _ida_allins.I196_jnh

I196_jnst = _ida_allins.I196_jnst

I196_jnv = _ida_allins.I196_jnv

I196_jnvt = _ida_allins.I196_jnvt

I196_jst = _ida_allins.I196_jst

I196_jv = _ida_allins.I196_jv

I196_jvt = _ida_allins.I196_jvt

I196_lcall = _ida_allins.I196_lcall

I196_ld = _ida_allins.I196_ld

I196_ldb = _ida_allins.I196_ldb

I196_ldbse = _ida_allins.I196_ldbse

I196_ldbze = _ida_allins.I196_ldbze

I196_ljmp = _ida_allins.I196_ljmp

I196_mul2 = _ida_allins.I196_mul2

I196_mul3 = _ida_allins.I196_mul3

I196_mulb2 = _ida_allins.I196_mulb2

I196_mulb3 = _ida_allins.I196_mulb3

I196_mulu2 = _ida_allins.I196_mulu2

I196_mulu3 = _ida_allins.I196_mulu3

I196_mulub2 = _ida_allins.I196_mulub2

I196_mulub3 = _ida_allins.I196_mulub3

I196_neg = _ida_allins.I196_neg

I196_negb = _ida_allins.I196_negb

I196_nop = _ida_allins.I196_nop

I196_norml = _ida_allins.I196_norml

I196_not = _ida_allins.I196_not

I196_notb = _ida_allins.I196_notb

I196_or = _ida_allins.I196_or

I196_orb = _ida_allins.I196_orb

I196_pop = _ida_allins.I196_pop

I196_popa = _ida_allins.I196_popa

I196_popf = _ida_allins.I196_popf

I196_push = _ida_allins.I196_push

I196_pusha = _ida_allins.I196_pusha

I196_pushf = _ida_allins.I196_pushf

I196_ret = _ida_allins.I196_ret

I196_rst = _ida_allins.I196_rst

I196_scall = _ida_allins.I196_scall

I196_setc = _ida_allins.I196_setc

I196_shl = _ida_allins.I196_shl

I196_shlb = _ida_allins.I196_shlb

I196_shll = _ida_allins.I196_shll

I196_shr = _ida_allins.I196_shr

I196_shra = _ida_allins.I196_shra

I196_shrab = _ida_allins.I196_shrab

I196_shral = _ida_allins.I196_shral

I196_shrb = _ida_allins.I196_shrb

I196_shrl = _ida_allins.I196_shrl

I196_sjmp = _ida_allins.I196_sjmp

I196_skip = _ida_allins.I196_skip

I196_st = _ida_allins.I196_st

I196_stb = _ida_allins.I196_stb

I196_sub2 = _ida_allins.I196_sub2

I196_sub3 = _ida_allins.I196_sub3

I196_subb2 = _ida_allins.I196_subb2

I196_subb3 = _ida_allins.I196_subb3

I196_subc = _ida_allins.I196_subc

I196_subcb = _ida_allins.I196_subcb

I196_tijmp = _ida_allins.I196_tijmp

I196_trap = _ida_allins.I196_trap

I196_xch = _ida_allins.I196_xch

I196_xchb = _ida_allins.I196_xchb

I196_xor = _ida_allins.I196_xor

I196_xorb = _ida_allins.I196_xorb

I196_ebmovi = _ida_allins.I196_ebmovi

I196_ebr = _ida_allins.I196_ebr

I196_ecall = _ida_allins.I196_ecall

I196_ejmp = _ida_allins.I196_ejmp

I196_eld = _ida_allins.I196_eld

I196_eldb = _ida_allins.I196_eldb

I196_est = _ida_allins.I196_est

I196_estb = _ida_allins.I196_estb

I196_last = _ida_allins.I196_last

SH3_null = _ida_allins.SH3_null

SH3_add = _ida_allins.SH3_add

SH3_addc = _ida_allins.SH3_addc

SH3_addv = _ida_allins.SH3_addv

SH3_and = _ida_allins.SH3_and

SH3_and_b = _ida_allins.SH3_and_b

SH3_bf = _ida_allins.SH3_bf

SH3_bf_s = _ida_allins.SH3_bf_s

SH3_bra = _ida_allins.SH3_bra

SH3_braf = _ida_allins.SH3_braf

SH3_bsr = _ida_allins.SH3_bsr

SH3_bsrf = _ida_allins.SH3_bsrf

SH3_bt = _ida_allins.SH3_bt

SH3_bt_s = _ida_allins.SH3_bt_s

SH3_clrmac = _ida_allins.SH3_clrmac

SH3_clrs = _ida_allins.SH3_clrs

SH3_clrt = _ida_allins.SH3_clrt

SH3_cmp_eq = _ida_allins.SH3_cmp_eq

SH3_cmp_ge = _ida_allins.SH3_cmp_ge

SH3_cmp_gt = _ida_allins.SH3_cmp_gt

SH3_cmp_hi = _ida_allins.SH3_cmp_hi

SH3_cmp_hs = _ida_allins.SH3_cmp_hs

SH3_cmp_pl = _ida_allins.SH3_cmp_pl

SH3_cmp_pz = _ida_allins.SH3_cmp_pz

SH3_cmp_str = _ida_allins.SH3_cmp_str

SH3_div0s = _ida_allins.SH3_div0s

SH3_div0u = _ida_allins.SH3_div0u

SH3_div1 = _ida_allins.SH3_div1

SH3_dmuls_l = _ida_allins.SH3_dmuls_l

SH3_dmulu_l = _ida_allins.SH3_dmulu_l

SH3_dt = _ida_allins.SH3_dt

SH3_exts_b = _ida_allins.SH3_exts_b

SH3_exts_w = _ida_allins.SH3_exts_w

SH3_extu_b = _ida_allins.SH3_extu_b

SH3_extu_w = _ida_allins.SH3_extu_w

SH3_jmp = _ida_allins.SH3_jmp

SH3_jsr = _ida_allins.SH3_jsr

SH3_ldc = _ida_allins.SH3_ldc

SH3_ldc_l = _ida_allins.SH3_ldc_l

SH3_lds = _ida_allins.SH3_lds

SH3_lds_l = _ida_allins.SH3_lds_l

SH3_ldtlb = _ida_allins.SH3_ldtlb

SH3_mac_w = _ida_allins.SH3_mac_w

SH3_mac_l = _ida_allins.SH3_mac_l

SH3_mov = _ida_allins.SH3_mov

SH3_mov_b = _ida_allins.SH3_mov_b

SH3_mov_w = _ida_allins.SH3_mov_w

SH3_mov_l = _ida_allins.SH3_mov_l

SH3_movi = _ida_allins.SH3_movi

SH3_movi_w = _ida_allins.SH3_movi_w

SH3_movi_l = _ida_allins.SH3_movi_l

SH3_movp_b = _ida_allins.SH3_movp_b

SH3_movp_w = _ida_allins.SH3_movp_w

SH3_movp_l = _ida_allins.SH3_movp_l

SH3_movs_b = _ida_allins.SH3_movs_b

SH3_movs_w = _ida_allins.SH3_movs_w

SH3_movs_l = _ida_allins.SH3_movs_l

SH3_mova = _ida_allins.SH3_mova

SH3_movt = _ida_allins.SH3_movt

SH3_mul = _ida_allins.SH3_mul

SH3_muls = _ida_allins.SH3_muls

SH3_mulu = _ida_allins.SH3_mulu

SH3_neg = _ida_allins.SH3_neg

SH3_negc = _ida_allins.SH3_negc

SH3_nop = _ida_allins.SH3_nop

SH3_not = _ida_allins.SH3_not

SH3_or = _ida_allins.SH3_or

SH3_or_b = _ida_allins.SH3_or_b

SH3_pref = _ida_allins.SH3_pref

SH3_rotcl = _ida_allins.SH3_rotcl

SH3_rotcr = _ida_allins.SH3_rotcr

SH3_rotl = _ida_allins.SH3_rotl

SH3_rotr = _ida_allins.SH3_rotr

SH3_rte = _ida_allins.SH3_rte

SH3_rts = _ida_allins.SH3_rts

SH3_sets = _ida_allins.SH3_sets

SH3_sett = _ida_allins.SH3_sett

SH3_shad = _ida_allins.SH3_shad

SH3_shal = _ida_allins.SH3_shal

SH3_shar = _ida_allins.SH3_shar

SH3_shld = _ida_allins.SH3_shld

SH3_shll = _ida_allins.SH3_shll

SH3_shll2 = _ida_allins.SH3_shll2

SH3_shll8 = _ida_allins.SH3_shll8

SH3_shll16 = _ida_allins.SH3_shll16

SH3_shlr = _ida_allins.SH3_shlr

SH3_shlr2 = _ida_allins.SH3_shlr2

SH3_shlr8 = _ida_allins.SH3_shlr8

SH3_shlr16 = _ida_allins.SH3_shlr16

SH3_sleep = _ida_allins.SH3_sleep

SH3_stc = _ida_allins.SH3_stc

SH3_stc_l = _ida_allins.SH3_stc_l

SH3_sts = _ida_allins.SH3_sts

SH3_sts_l = _ida_allins.SH3_sts_l

SH3_sub = _ida_allins.SH3_sub

SH3_subc = _ida_allins.SH3_subc

SH3_subv = _ida_allins.SH3_subv

SH3_swap_b = _ida_allins.SH3_swap_b

SH3_swap_w = _ida_allins.SH3_swap_w

SH3_tas_b = _ida_allins.SH3_tas_b

SH3_trapa = _ida_allins.SH3_trapa

SH3_tst = _ida_allins.SH3_tst

SH3_tst_b = _ida_allins.SH3_tst_b

SH3_xor = _ida_allins.SH3_xor

SH3_xor_b = _ida_allins.SH3_xor_b

SH3_xtrct = _ida_allins.SH3_xtrct

SH4_fabs = _ida_allins.SH4_fabs

SH4_fadd = _ida_allins.SH4_fadd

SH4_fcmp_eq = _ida_allins.SH4_fcmp_eq

SH4_fcmp_gt = _ida_allins.SH4_fcmp_gt

SH4_fcnvds = _ida_allins.SH4_fcnvds

SH4_fcnvsd = _ida_allins.SH4_fcnvsd

SH4_fdiv = _ida_allins.SH4_fdiv

SH4_fipr = _ida_allins.SH4_fipr

SH4_fldi0 = _ida_allins.SH4_fldi0

SH4_fldi1 = _ida_allins.SH4_fldi1

SH4_flds = _ida_allins.SH4_flds

SH4_float = _ida_allins.SH4_float

SH4_fmac = _ida_allins.SH4_fmac

SH4_fmov = _ida_allins.SH4_fmov

SH4_fmov_s = _ida_allins.SH4_fmov_s

SH4_fmovex = _ida_allins.SH4_fmovex

SH4_fmul = _ida_allins.SH4_fmul

SH4_fneg = _ida_allins.SH4_fneg

SH4_frchg = _ida_allins.SH4_frchg

SH4_fschg = _ida_allins.SH4_fschg

SH4_fsqrt = _ida_allins.SH4_fsqrt

SH4_fsts = _ida_allins.SH4_fsts

SH4_fsub = _ida_allins.SH4_fsub

SH4_ftrc = _ida_allins.SH4_ftrc

SH4_ftrv = _ida_allins.SH4_ftrv

SH4_ftstn = _ida_allins.SH4_ftstn

SH4_movca_l = _ida_allins.SH4_movca_l

SH4_ocbi = _ida_allins.SH4_ocbi

SH4_ocbp = _ida_allins.SH4_ocbp

SH4_ocbwb = _ida_allins.SH4_ocbwb

SH4_fsca = _ida_allins.SH4_fsca

SH2a_band_b = _ida_allins.SH2a_band_b

SH2a_bandnot_b = _ida_allins.SH2a_bandnot_b

SH2a_bclr = _ida_allins.SH2a_bclr

SH2a_bclr_b = _ida_allins.SH2a_bclr_b

SH2a_bld = _ida_allins.SH2a_bld

SH2a_bld_b = _ida_allins.SH2a_bld_b

SH2a_bldnot_b = _ida_allins.SH2a_bldnot_b

SH2a_bor_b = _ida_allins.SH2a_bor_b

SH2a_bornot_b = _ida_allins.SH2a_bornot_b

SH2a_bset = _ida_allins.SH2a_bset

SH2a_bset_b = _ida_allins.SH2a_bset_b

SH2a_bst = _ida_allins.SH2a_bst

SH2a_bst_b = _ida_allins.SH2a_bst_b

SH2a_bxor_b = _ida_allins.SH2a_bxor_b

SH2a_clips_b = _ida_allins.SH2a_clips_b

SH2a_clips_w = _ida_allins.SH2a_clips_w

SH2a_clipu_b = _ida_allins.SH2a_clipu_b

SH2a_clipu_w = _ida_allins.SH2a_clipu_w

SH2a_divs = _ida_allins.SH2a_divs

SH2a_divu = _ida_allins.SH2a_divu

SH2a_jsr_n = _ida_allins.SH2a_jsr_n

SH2a_ldbank = _ida_allins.SH2a_ldbank

SH2a_movi20 = _ida_allins.SH2a_movi20

SH2a_movi20s = _ida_allins.SH2a_movi20s

SH2a_movml_l = _ida_allins.SH2a_movml_l

SH2a_movmu_l = _ida_allins.SH2a_movmu_l

SH2a_movrt = _ida_allins.SH2a_movrt

SH2a_movu_b = _ida_allins.SH2a_movu_b

SH2a_movu_w = _ida_allins.SH2a_movu_w

SH2a_mulr = _ida_allins.SH2a_mulr

SH2a_nott = _ida_allins.SH2a_nott

SH2a_resbank = _ida_allins.SH2a_resbank

SH2a_rts_n = _ida_allins.SH2a_rts_n

SH2a_rtv_n = _ida_allins.SH2a_rtv_n

SH2a_stbank = _ida_allins.SH2a_stbank

SH4a_movco_l = _ida_allins.SH4a_movco_l

SH4a_movli_l = _ida_allins.SH4a_movli_l

SH4a_movua_l = _ida_allins.SH4a_movua_l

SH4a_icbi = _ida_allins.SH4a_icbi

SH4a_prefi = _ida_allins.SH4a_prefi

SH4a_synco = _ida_allins.SH4a_synco

SH4a_fsrra = _ida_allins.SH4a_fsrra

SH4a_fpchg = _ida_allins.SH4a_fpchg

SH4_last = _ida_allins.SH4_last

Z8_null = _ida_allins.Z8_null

Z8_adc = _ida_allins.Z8_adc

Z8_add = _ida_allins.Z8_add

Z8_and = _ida_allins.Z8_and

Z8_call = _ida_allins.Z8_call

Z8_ccf = _ida_allins.Z8_ccf

Z8_clr = _ida_allins.Z8_clr

Z8_com = _ida_allins.Z8_com

Z8_cp = _ida_allins.Z8_cp

Z8_da = _ida_allins.Z8_da

Z8_dec = _ida_allins.Z8_dec

Z8_decw = _ida_allins.Z8_decw

Z8_di = _ida_allins.Z8_di

Z8_djnz = _ida_allins.Z8_djnz

Z8_ei = _ida_allins.Z8_ei

Z8_halt = _ida_allins.Z8_halt

Z8_inc = _ida_allins.Z8_inc

Z8_incw = _ida_allins.Z8_incw

Z8_iret = _ida_allins.Z8_iret

Z8_jp = _ida_allins.Z8_jp

Z8_jpcond = _ida_allins.Z8_jpcond

Z8_jr = _ida_allins.Z8_jr

Z8_jrcond = _ida_allins.Z8_jrcond

Z8_ld = _ida_allins.Z8_ld

Z8_ldc = _ida_allins.Z8_ldc

Z8_ldci = _ida_allins.Z8_ldci

Z8_lde = _ida_allins.Z8_lde

Z8_ldei = _ida_allins.Z8_ldei

Z8_nop = _ida_allins.Z8_nop

Z8_or = _ida_allins.Z8_or

Z8_pop = _ida_allins.Z8_pop

Z8_push = _ida_allins.Z8_push

Z8_rcf = _ida_allins.Z8_rcf

Z8_ret = _ida_allins.Z8_ret

Z8_rl = _ida_allins.Z8_rl

Z8_rlc = _ida_allins.Z8_rlc

Z8_rr = _ida_allins.Z8_rr

Z8_rrc = _ida_allins.Z8_rrc

Z8_sbc = _ida_allins.Z8_sbc

Z8_scf = _ida_allins.Z8_scf

Z8_sra = _ida_allins.Z8_sra

Z8_srp = _ida_allins.Z8_srp

Z8_stop = _ida_allins.Z8_stop

Z8_sub = _ida_allins.Z8_sub

Z8_swap = _ida_allins.Z8_swap

Z8_tm = _ida_allins.Z8_tm

Z8_tcm = _ida_allins.Z8_tcm

Z8_xor = _ida_allins.Z8_xor

Z8_wdh = _ida_allins.Z8_wdh

Z8_wdt = _ida_allins.Z8_wdt

Z8_last = _ida_allins.Z8_last

AVR_null = _ida_allins.AVR_null

AVR_add = _ida_allins.AVR_add

AVR_adc = _ida_allins.AVR_adc

AVR_adiw = _ida_allins.AVR_adiw

AVR_sub = _ida_allins.AVR_sub

AVR_subi = _ida_allins.AVR_subi

AVR_sbc = _ida_allins.AVR_sbc

AVR_sbci = _ida_allins.AVR_sbci

AVR_sbiw = _ida_allins.AVR_sbiw

AVR_and = _ida_allins.AVR_and

AVR_andi = _ida_allins.AVR_andi

AVR_or = _ida_allins.AVR_or

AVR_ori = _ida_allins.AVR_ori

AVR_eor = _ida_allins.AVR_eor

AVR_com = _ida_allins.AVR_com

AVR_neg = _ida_allins.AVR_neg

AVR_sbr = _ida_allins.AVR_sbr

AVR_cbr = _ida_allins.AVR_cbr

AVR_inc = _ida_allins.AVR_inc

AVR_dec = _ida_allins.AVR_dec

AVR_tst = _ida_allins.AVR_tst

AVR_clr = _ida_allins.AVR_clr

AVR_ser = _ida_allins.AVR_ser

AVR_cp = _ida_allins.AVR_cp

AVR_cpc = _ida_allins.AVR_cpc

AVR_cpi = _ida_allins.AVR_cpi

AVR_mul = _ida_allins.AVR_mul

AVR_rjmp = _ida_allins.AVR_rjmp

AVR_ijmp = _ida_allins.AVR_ijmp

AVR_jmp = _ida_allins.AVR_jmp

AVR_rcall = _ida_allins.AVR_rcall

AVR_icall = _ida_allins.AVR_icall

AVR_call = _ida_allins.AVR_call

AVR_ret = _ida_allins.AVR_ret

AVR_reti = _ida_allins.AVR_reti

AVR_cpse = _ida_allins.AVR_cpse

AVR_sbrc = _ida_allins.AVR_sbrc

AVR_sbrs = _ida_allins.AVR_sbrs

AVR_sbic = _ida_allins.AVR_sbic

AVR_sbis = _ida_allins.AVR_sbis

AVR_brbs = _ida_allins.AVR_brbs

AVR_brbc = _ida_allins.AVR_brbc

AVR_breq = _ida_allins.AVR_breq

AVR_brne = _ida_allins.AVR_brne

AVR_brcs = _ida_allins.AVR_brcs

AVR_brcc = _ida_allins.AVR_brcc

AVR_brsh = _ida_allins.AVR_brsh

AVR_brlo = _ida_allins.AVR_brlo

AVR_brmi = _ida_allins.AVR_brmi

AVR_brpl = _ida_allins.AVR_brpl

AVR_brge = _ida_allins.AVR_brge

AVR_brlt = _ida_allins.AVR_brlt

AVR_brhs = _ida_allins.AVR_brhs

AVR_brhc = _ida_allins.AVR_brhc

AVR_brts = _ida_allins.AVR_brts

AVR_brtc = _ida_allins.AVR_brtc

AVR_brvs = _ida_allins.AVR_brvs

AVR_brvc = _ida_allins.AVR_brvc

AVR_brie = _ida_allins.AVR_brie

AVR_brid = _ida_allins.AVR_brid

AVR_mov = _ida_allins.AVR_mov

AVR_ldi = _ida_allins.AVR_ldi

AVR_lds = _ida_allins.AVR_lds

AVR_ld = _ida_allins.AVR_ld

AVR_ldd = _ida_allins.AVR_ldd

AVR_sts = _ida_allins.AVR_sts

AVR_st = _ida_allins.AVR_st

AVR_std = _ida_allins.AVR_std

AVR_lpm = _ida_allins.AVR_lpm

AVR_in = _ida_allins.AVR_in

AVR_out = _ida_allins.AVR_out

AVR_push = _ida_allins.AVR_push

AVR_pop = _ida_allins.AVR_pop

AVR_lsl = _ida_allins.AVR_lsl

AVR_lsr = _ida_allins.AVR_lsr

AVR_rol = _ida_allins.AVR_rol

AVR_ror = _ida_allins.AVR_ror

AVR_asr = _ida_allins.AVR_asr

AVR_swap = _ida_allins.AVR_swap

AVR_bset = _ida_allins.AVR_bset

AVR_bclr = _ida_allins.AVR_bclr

AVR_sbi = _ida_allins.AVR_sbi

AVR_cbi = _ida_allins.AVR_cbi

AVR_bst = _ida_allins.AVR_bst

AVR_bld = _ida_allins.AVR_bld

AVR_sec = _ida_allins.AVR_sec

AVR_clc = _ida_allins.AVR_clc

AVR_sen = _ida_allins.AVR_sen

AVR_cln = _ida_allins.AVR_cln

AVR_sez = _ida_allins.AVR_sez

AVR_clz = _ida_allins.AVR_clz

AVR_sei = _ida_allins.AVR_sei

AVR_cli = _ida_allins.AVR_cli

AVR_ses = _ida_allins.AVR_ses

AVR_cls = _ida_allins.AVR_cls

AVR_sev = _ida_allins.AVR_sev

AVR_clv = _ida_allins.AVR_clv

AVR_set = _ida_allins.AVR_set

AVR_clt = _ida_allins.AVR_clt

AVR_seh = _ida_allins.AVR_seh

AVR_clh = _ida_allins.AVR_clh

AVR_nop = _ida_allins.AVR_nop

AVR_sleep = _ida_allins.AVR_sleep

AVR_wdr = _ida_allins.AVR_wdr

AVR_elpm = _ida_allins.AVR_elpm

AVR_espm = _ida_allins.AVR_espm

AVR_fmul = _ida_allins.AVR_fmul

AVR_fmuls = _ida_allins.AVR_fmuls

AVR_fmulsu = _ida_allins.AVR_fmulsu

AVR_movw = _ida_allins.AVR_movw

AVR_muls = _ida_allins.AVR_muls

AVR_mulsu = _ida_allins.AVR_mulsu

AVR_spm = _ida_allins.AVR_spm

AVR_eicall = _ida_allins.AVR_eicall

AVR_eijmp = _ida_allins.AVR_eijmp

AVR_des = _ida_allins.AVR_des

AVR_lac = _ida_allins.AVR_lac

AVR_las = _ida_allins.AVR_las

AVR_lat = _ida_allins.AVR_lat

AVR_xch = _ida_allins.AVR_xch

AVR_last = _ida_allins.AVR_last

MIPS_null = _ida_allins.MIPS_null

MIPS_add = _ida_allins.MIPS_add

MIPS_addu = _ida_allins.MIPS_addu

MIPS_and = _ida_allins.MIPS_and

MIPS_dadd = _ida_allins.MIPS_dadd

MIPS_daddu = _ida_allins.MIPS_daddu

MIPS_dsub = _ida_allins.MIPS_dsub

MIPS_dsubu = _ida_allins.MIPS_dsubu

MIPS_nor = _ida_allins.MIPS_nor

MIPS_or = _ida_allins.MIPS_or

MIPS_slt = _ida_allins.MIPS_slt

MIPS_sltu = _ida_allins.MIPS_sltu

MIPS_sub = _ida_allins.MIPS_sub

MIPS_subu = _ida_allins.MIPS_subu

MIPS_xor = _ida_allins.MIPS_xor

MIPS_dsll = _ida_allins.MIPS_dsll

MIPS_dsll32 = _ida_allins.MIPS_dsll32

MIPS_dsra = _ida_allins.MIPS_dsra

MIPS_dsra32 = _ida_allins.MIPS_dsra32

MIPS_dsrl = _ida_allins.MIPS_dsrl

MIPS_dsrl32 = _ida_allins.MIPS_dsrl32

MIPS_sll = _ida_allins.MIPS_sll

MIPS_sra = _ida_allins.MIPS_sra

MIPS_srl = _ida_allins.MIPS_srl

MIPS_dsllv = _ida_allins.MIPS_dsllv

MIPS_dsrav = _ida_allins.MIPS_dsrav

MIPS_dsrlv = _ida_allins.MIPS_dsrlv

MIPS_sllv = _ida_allins.MIPS_sllv

MIPS_srav = _ida_allins.MIPS_srav

MIPS_srlv = _ida_allins.MIPS_srlv

MIPS_addi = _ida_allins.MIPS_addi

MIPS_addiu = _ida_allins.MIPS_addiu

MIPS_daddi = _ida_allins.MIPS_daddi

MIPS_daddiu = _ida_allins.MIPS_daddiu

MIPS_slti = _ida_allins.MIPS_slti

MIPS_sltiu = _ida_allins.MIPS_sltiu

MIPS_andi = _ida_allins.MIPS_andi

MIPS_ori = _ida_allins.MIPS_ori

MIPS_xori = _ida_allins.MIPS_xori

MIPS_teq = _ida_allins.MIPS_teq

MIPS_tge = _ida_allins.MIPS_tge

MIPS_tgeu = _ida_allins.MIPS_tgeu

MIPS_tlt = _ida_allins.MIPS_tlt

MIPS_tltu = _ida_allins.MIPS_tltu

MIPS_tne = _ida_allins.MIPS_tne

MIPS_cfc1 = _ida_allins.MIPS_cfc1

MIPS_cfc2 = _ida_allins.MIPS_cfc2

MIPS_ctc1 = _ida_allins.MIPS_ctc1

MIPS_ctc2 = _ida_allins.MIPS_ctc2

MIPS_dmfc0 = _ida_allins.MIPS_dmfc0

MIPS_qmfc2 = _ida_allins.MIPS_qmfc2

MIPS_dmtc0 = _ida_allins.MIPS_dmtc0

MIPS_qmtc2 = _ida_allins.MIPS_qmtc2

MIPS_mfc0 = _ida_allins.MIPS_mfc0

MIPS_mfc1 = _ida_allins.MIPS_mfc1

MIPS_mfc2 = _ida_allins.MIPS_mfc2

MIPS_mtc0 = _ida_allins.MIPS_mtc0

MIPS_mtc1 = _ida_allins.MIPS_mtc1

MIPS_mtc2 = _ida_allins.MIPS_mtc2

MIPS_teqi = _ida_allins.MIPS_teqi

MIPS_tgei = _ida_allins.MIPS_tgei

MIPS_tgeiu = _ida_allins.MIPS_tgeiu

MIPS_tlti = _ida_allins.MIPS_tlti

MIPS_tltiu = _ida_allins.MIPS_tltiu

MIPS_tnei = _ida_allins.MIPS_tnei

MIPS_ddiv = _ida_allins.MIPS_ddiv

MIPS_ddivu = _ida_allins.MIPS_ddivu

MIPS_div = _ida_allins.MIPS_div

MIPS_divu = _ida_allins.MIPS_divu

MIPS_dmult = _ida_allins.MIPS_dmult

MIPS_dmultu = _ida_allins.MIPS_dmultu

MIPS_mult = _ida_allins.MIPS_mult

MIPS_multu = _ida_allins.MIPS_multu

MIPS_mthi = _ida_allins.MIPS_mthi

MIPS_mtlo = _ida_allins.MIPS_mtlo

MIPS_mfhi = _ida_allins.MIPS_mfhi

MIPS_mflo = _ida_allins.MIPS_mflo

MIPS_cop0 = _ida_allins.MIPS_cop0

MIPS_cop1 = _ida_allins.MIPS_cop1

MIPS_cop2 = _ida_allins.MIPS_cop2

MIPS_break = _ida_allins.MIPS_break

MIPS_syscall = _ida_allins.MIPS_syscall

MIPS_bc0f = _ida_allins.MIPS_bc0f

MIPS_bc1f = _ida_allins.MIPS_bc1f

MIPS_bc2f = _ida_allins.MIPS_bc2f

MIPS_bc3f = _ida_allins.MIPS_bc3f

MIPS_bc0fl = _ida_allins.MIPS_bc0fl

MIPS_bc1fl = _ida_allins.MIPS_bc1fl

MIPS_bc2fl = _ida_allins.MIPS_bc2fl

MIPS_bc3fl = _ida_allins.MIPS_bc3fl

MIPS_bc0t = _ida_allins.MIPS_bc0t

MIPS_bc1t = _ida_allins.MIPS_bc1t

MIPS_bc2t = _ida_allins.MIPS_bc2t

MIPS_bc3t = _ida_allins.MIPS_bc3t

MIPS_bc0tl = _ida_allins.MIPS_bc0tl

MIPS_bc1tl = _ida_allins.MIPS_bc1tl

MIPS_bc2tl = _ida_allins.MIPS_bc2tl

MIPS_bc3tl = _ida_allins.MIPS_bc3tl

MIPS_bgez = _ida_allins.MIPS_bgez

MIPS_bgezal = _ida_allins.MIPS_bgezal

MIPS_bgezall = _ida_allins.MIPS_bgezall

MIPS_bgezl = _ida_allins.MIPS_bgezl

MIPS_bgtz = _ida_allins.MIPS_bgtz

MIPS_bgtzl = _ida_allins.MIPS_bgtzl

MIPS_blez = _ida_allins.MIPS_blez

MIPS_blezl = _ida_allins.MIPS_blezl

MIPS_bltz = _ida_allins.MIPS_bltz

MIPS_bltzal = _ida_allins.MIPS_bltzal

MIPS_bltzall = _ida_allins.MIPS_bltzall

MIPS_bltzl = _ida_allins.MIPS_bltzl

MIPS_beq = _ida_allins.MIPS_beq

MIPS_beql = _ida_allins.MIPS_beql

MIPS_bne = _ida_allins.MIPS_bne

MIPS_bnel = _ida_allins.MIPS_bnel

MIPS_jalr = _ida_allins.MIPS_jalr

MIPS_j = _ida_allins.MIPS_j

MIPS_jr = _ida_allins.MIPS_jr

MIPS_jal = _ida_allins.MIPS_jal

MIPS_jalx = _ida_allins.MIPS_jalx

MIPS_cache = _ida_allins.MIPS_cache

MIPS_lb = _ida_allins.MIPS_lb

MIPS_lbu = _ida_allins.MIPS_lbu

MIPS_ldl = _ida_allins.MIPS_ldl

MIPS_ldr = _ida_allins.MIPS_ldr

MIPS_lwl = _ida_allins.MIPS_lwl

MIPS_lwr = _ida_allins.MIPS_lwr

MIPS_ld = _ida_allins.MIPS_ld

MIPS_lld = _ida_allins.MIPS_lld

MIPS_ldc1 = _ida_allins.MIPS_ldc1

MIPS_ldc2 = _ida_allins.MIPS_ldc2

MIPS_ll = _ida_allins.MIPS_ll

MIPS_lw = _ida_allins.MIPS_lw

MIPS_lwu = _ida_allins.MIPS_lwu

MIPS_lh = _ida_allins.MIPS_lh

MIPS_lhu = _ida_allins.MIPS_lhu

MIPS_lui = _ida_allins.MIPS_lui

MIPS_lwc1 = _ida_allins.MIPS_lwc1

MIPS_lwc2 = _ida_allins.MIPS_lwc2

MIPS_sb = _ida_allins.MIPS_sb

MIPS_sdl = _ida_allins.MIPS_sdl

MIPS_sdr = _ida_allins.MIPS_sdr

MIPS_swl = _ida_allins.MIPS_swl

MIPS_swr = _ida_allins.MIPS_swr

MIPS_scd = _ida_allins.MIPS_scd

MIPS_sd = _ida_allins.MIPS_sd

MIPS_sdc1 = _ida_allins.MIPS_sdc1

MIPS_sdc2 = _ida_allins.MIPS_sdc2

MIPS_sc = _ida_allins.MIPS_sc

MIPS_sw = _ida_allins.MIPS_sw

MIPS_sh = _ida_allins.MIPS_sh

MIPS_swc1 = _ida_allins.MIPS_swc1

MIPS_swc2 = _ida_allins.MIPS_swc2

MIPS_sync = _ida_allins.MIPS_sync

MIPS_eret = _ida_allins.MIPS_eret

MIPS_tlbp = _ida_allins.MIPS_tlbp

MIPS_tlbr = _ida_allins.MIPS_tlbr

MIPS_tlbwi = _ida_allins.MIPS_tlbwi

MIPS_tlbwr = _ida_allins.MIPS_tlbwr

MIPS_fadd = _ida_allins.MIPS_fadd

MIPS_fsub = _ida_allins.MIPS_fsub

MIPS_fmul = _ida_allins.MIPS_fmul

MIPS_fdiv = _ida_allins.MIPS_fdiv

MIPS_fabs = _ida_allins.MIPS_fabs

MIPS_fcvt_s = _ida_allins.MIPS_fcvt_s

MIPS_fcvt_d = _ida_allins.MIPS_fcvt_d

MIPS_fcvt_w = _ida_allins.MIPS_fcvt_w

MIPS_fcvt_l = _ida_allins.MIPS_fcvt_l

MIPS_fround_l = _ida_allins.MIPS_fround_l

MIPS_ftrunc_l = _ida_allins.MIPS_ftrunc_l

MIPS_fceil_l = _ida_allins.MIPS_fceil_l

MIPS_ffloor_l = _ida_allins.MIPS_ffloor_l

MIPS_fround_w = _ida_allins.MIPS_fround_w

MIPS_ftrunc_w = _ida_allins.MIPS_ftrunc_w

MIPS_fceil_w = _ida_allins.MIPS_fceil_w

MIPS_ffloor_w = _ida_allins.MIPS_ffloor_w

MIPS_fmov = _ida_allins.MIPS_fmov

MIPS_fneg = _ida_allins.MIPS_fneg

MIPS_fsqrt = _ida_allins.MIPS_fsqrt

MIPS_fc_f = _ida_allins.MIPS_fc_f

MIPS_fc_un = _ida_allins.MIPS_fc_un

MIPS_fc_eq = _ida_allins.MIPS_fc_eq

MIPS_fc_ueq = _ida_allins.MIPS_fc_ueq

MIPS_fc_olt = _ida_allins.MIPS_fc_olt

MIPS_fc_ult = _ida_allins.MIPS_fc_ult

MIPS_fc_ole = _ida_allins.MIPS_fc_ole

MIPS_fc_ule = _ida_allins.MIPS_fc_ule

MIPS_fc_sf = _ida_allins.MIPS_fc_sf

MIPS_fc_ngle = _ida_allins.MIPS_fc_ngle

MIPS_fc_seq = _ida_allins.MIPS_fc_seq

MIPS_fc_ngl = _ida_allins.MIPS_fc_ngl

MIPS_fc_lt = _ida_allins.MIPS_fc_lt

MIPS_fc_nge = _ida_allins.MIPS_fc_nge

MIPS_fc_le = _ida_allins.MIPS_fc_le

MIPS_fc_ngt = _ida_allins.MIPS_fc_ngt

MIPS_nop = _ida_allins.MIPS_nop

MIPS_mov = _ida_allins.MIPS_mov

MIPS_neg = _ida_allins.MIPS_neg

MIPS_negu = _ida_allins.MIPS_negu

MIPS_bnez = _ida_allins.MIPS_bnez

MIPS_bnezl = _ida_allins.MIPS_bnezl

MIPS_beqz = _ida_allins.MIPS_beqz

MIPS_beqzl = _ida_allins.MIPS_beqzl

MIPS_b = _ida_allins.MIPS_b

MIPS_bal = _ida_allins.MIPS_bal

MIPS_li = _ida_allins.MIPS_li

MIPS_la = _ida_allins.MIPS_la

MIPS_pref = _ida_allins.MIPS_pref

MIPS_ldxc1 = _ida_allins.MIPS_ldxc1

MIPS_lwxc1 = _ida_allins.MIPS_lwxc1

MIPS_sdxc1 = _ida_allins.MIPS_sdxc1

MIPS_swxc1 = _ida_allins.MIPS_swxc1

MIPS_madd_s = _ida_allins.MIPS_madd_s

MIPS_madd_d = _ida_allins.MIPS_madd_d

MIPS_msub_s = _ida_allins.MIPS_msub_s

MIPS_msub_d = _ida_allins.MIPS_msub_d

MIPS_movf = _ida_allins.MIPS_movf

MIPS_movt = _ida_allins.MIPS_movt

MIPS_movn = _ida_allins.MIPS_movn

MIPS_movz = _ida_allins.MIPS_movz

MIPS_fmovf = _ida_allins.MIPS_fmovf

MIPS_fmovt = _ida_allins.MIPS_fmovt

MIPS_fmovn = _ida_allins.MIPS_fmovn

MIPS_fmovz = _ida_allins.MIPS_fmovz

MIPS_nmadd_s = _ida_allins.MIPS_nmadd_s

MIPS_nmadd_d = _ida_allins.MIPS_nmadd_d

MIPS_nmsub_s = _ida_allins.MIPS_nmsub_s

MIPS_nmsub_d = _ida_allins.MIPS_nmsub_d

MIPS_prefx = _ida_allins.MIPS_prefx

MIPS_frecip = _ida_allins.MIPS_frecip

MIPS_frsqrt = _ida_allins.MIPS_frsqrt

MIPS_lbv = _ida_allins.MIPS_lbv

MIPS_lsv = _ida_allins.MIPS_lsv

MIPS_llv = _ida_allins.MIPS_llv

MIPS_ldv = _ida_allins.MIPS_ldv

MIPS_lqv = _ida_allins.MIPS_lqv

MIPS_lrv = _ida_allins.MIPS_lrv

MIPS_lpv = _ida_allins.MIPS_lpv

MIPS_luv = _ida_allins.MIPS_luv

MIPS_lhv = _ida_allins.MIPS_lhv

MIPS_lfv = _ida_allins.MIPS_lfv

MIPS_lwv = _ida_allins.MIPS_lwv

MIPS_ltv = _ida_allins.MIPS_ltv

MIPS_sbv = _ida_allins.MIPS_sbv

MIPS_ssv = _ida_allins.MIPS_ssv

MIPS_slv = _ida_allins.MIPS_slv

MIPS_sdv = _ida_allins.MIPS_sdv

MIPS_sqv = _ida_allins.MIPS_sqv

MIPS_srv = _ida_allins.MIPS_srv

MIPS_spv = _ida_allins.MIPS_spv

MIPS_suv = _ida_allins.MIPS_suv

MIPS_shv = _ida_allins.MIPS_shv

MIPS_sfv = _ida_allins.MIPS_sfv

MIPS_swv = _ida_allins.MIPS_swv

MIPS_stv = _ida_allins.MIPS_stv

MIPS_vmulf = _ida_allins.MIPS_vmulf

MIPS_vmacf = _ida_allins.MIPS_vmacf

MIPS_vmulu = _ida_allins.MIPS_vmulu

MIPS_vmacu = _ida_allins.MIPS_vmacu

MIPS_vrndp = _ida_allins.MIPS_vrndp

MIPS_vrndn = _ida_allins.MIPS_vrndn

MIPS_vmulq = _ida_allins.MIPS_vmulq

MIPS_vmacq = _ida_allins.MIPS_vmacq

MIPS_vmudh = _ida_allins.MIPS_vmudh

MIPS_vmadh = _ida_allins.MIPS_vmadh

MIPS_vmudm = _ida_allins.MIPS_vmudm

MIPS_vmadm = _ida_allins.MIPS_vmadm

MIPS_vmudn = _ida_allins.MIPS_vmudn

MIPS_vmadn = _ida_allins.MIPS_vmadn

MIPS_vmudl = _ida_allins.MIPS_vmudl

MIPS_vmadl = _ida_allins.MIPS_vmadl

MIPS_vadd = _ida_allins.MIPS_vadd

MIPS_vsub = _ida_allins.MIPS_vsub

MIPS_vsut = _ida_allins.MIPS_vsut

MIPS_vabs = _ida_allins.MIPS_vabs

MIPS_vaddc = _ida_allins.MIPS_vaddc

MIPS_vsubc = _ida_allins.MIPS_vsubc

MIPS_vaddb = _ida_allins.MIPS_vaddb

MIPS_vsubb = _ida_allins.MIPS_vsubb

MIPS_vaccb = _ida_allins.MIPS_vaccb

MIPS_vsucb = _ida_allins.MIPS_vsucb

MIPS_vsad = _ida_allins.MIPS_vsad

MIPS_vsac = _ida_allins.MIPS_vsac

MIPS_vsum = _ida_allins.MIPS_vsum

MIPS_vsaw = _ida_allins.MIPS_vsaw

MIPS_vlt = _ida_allins.MIPS_vlt

MIPS_veq = _ida_allins.MIPS_veq

MIPS_vne = _ida_allins.MIPS_vne

MIPS_vge = _ida_allins.MIPS_vge

MIPS_vcl = _ida_allins.MIPS_vcl

MIPS_vch = _ida_allins.MIPS_vch

MIPS_vcr = _ida_allins.MIPS_vcr

MIPS_vmrg = _ida_allins.MIPS_vmrg

MIPS_vand = _ida_allins.MIPS_vand

MIPS_vnand = _ida_allins.MIPS_vnand

MIPS_vor = _ida_allins.MIPS_vor

MIPS_vnor = _ida_allins.MIPS_vnor

MIPS_vxor = _ida_allins.MIPS_vxor

MIPS_vnxor = _ida_allins.MIPS_vnxor

MIPS_vnoop = _ida_allins.MIPS_vnoop

MIPS_vmov = _ida_allins.MIPS_vmov

MIPS_vrcp = _ida_allins.MIPS_vrcp

MIPS_vrsq = _ida_allins.MIPS_vrsq

MIPS_vrcph = _ida_allins.MIPS_vrcph

MIPS_vrsqh = _ida_allins.MIPS_vrsqh

MIPS_vrcpl = _ida_allins.MIPS_vrcpl

MIPS_vrsql = _ida_allins.MIPS_vrsql

MIPS_vinst = _ida_allins.MIPS_vinst

MIPS_vextt = _ida_allins.MIPS_vextt

MIPS_vinsq = _ida_allins.MIPS_vinsq

MIPS_vextq = _ida_allins.MIPS_vextq

MIPS_vinsn = _ida_allins.MIPS_vinsn

MIPS_vextn = _ida_allins.MIPS_vextn

MIPS_cfc0 = _ida_allins.MIPS_cfc0

MIPS_ctc0 = _ida_allins.MIPS_ctc0

MIPS_mtsa = _ida_allins.MIPS_mtsa

MIPS_R5900_first = _ida_allins.MIPS_R5900_first

MIPS_mfsa = _ida_allins.MIPS_mfsa

MIPS_mtsab = _ida_allins.MIPS_mtsab

MIPS_mtsah = _ida_allins.MIPS_mtsah

MIPS_fadda = _ida_allins.MIPS_fadda

MIPS_fsuba = _ida_allins.MIPS_fsuba

MIPS_fmula = _ida_allins.MIPS_fmula

MIPS_fmadda = _ida_allins.MIPS_fmadda

MIPS_fmsuba = _ida_allins.MIPS_fmsuba

MIPS_fmadd = _ida_allins.MIPS_fmadd

MIPS_fmsub = _ida_allins.MIPS_fmsub

MIPS_fmax = _ida_allins.MIPS_fmax

MIPS_fmin = _ida_allins.MIPS_fmin

MIPS_plzcw = _ida_allins.MIPS_plzcw

MIPS_mthi1 = _ida_allins.MIPS_mthi1

MIPS_mtlo1 = _ida_allins.MIPS_mtlo1

MIPS_pmthl_lw = _ida_allins.MIPS_pmthl_lw

MIPS_pmthi = _ida_allins.MIPS_pmthi

MIPS_pmtlo = _ida_allins.MIPS_pmtlo

MIPS_div1 = _ida_allins.MIPS_div1

MIPS_divu1 = _ida_allins.MIPS_divu1

MIPS_pdivw = _ida_allins.MIPS_pdivw

MIPS_pdivuw = _ida_allins.MIPS_pdivuw

MIPS_pdivbw = _ida_allins.MIPS_pdivbw

MIPS_paddw = _ida_allins.MIPS_paddw

MIPS_pmaddw = _ida_allins.MIPS_pmaddw

MIPS_mult1 = _ida_allins.MIPS_mult1

MIPS_multu1 = _ida_allins.MIPS_multu1

MIPS_madd1 = _ida_allins.MIPS_madd1

MIPS_maddu1 = _ida_allins.MIPS_maddu1

MIPS_pmadduw = _ida_allins.MIPS_pmadduw

MIPS_psubw = _ida_allins.MIPS_psubw

MIPS_pcgtw = _ida_allins.MIPS_pcgtw

MIPS_psllvw = _ida_allins.MIPS_psllvw

MIPS_pceqw = _ida_allins.MIPS_pceqw

MIPS_pmaxw = _ida_allins.MIPS_pmaxw

MIPS_psrlvw = _ida_allins.MIPS_psrlvw

MIPS_pminw = _ida_allins.MIPS_pminw

MIPS_psravw = _ida_allins.MIPS_psravw

MIPS_paddh = _ida_allins.MIPS_paddh

MIPS_pmsubw = _ida_allins.MIPS_pmsubw

MIPS_padsbh = _ida_allins.MIPS_padsbh

MIPS_psubh = _ida_allins.MIPS_psubh

MIPS_pcgth = _ida_allins.MIPS_pcgth

MIPS_pceqh = _ida_allins.MIPS_pceqh

MIPS_pmaxh = _ida_allins.MIPS_pmaxh

MIPS_pminh = _ida_allins.MIPS_pminh

MIPS_paddb = _ida_allins.MIPS_paddb

MIPS_psubb = _ida_allins.MIPS_psubb

MIPS_pcgtb = _ida_allins.MIPS_pcgtb

MIPS_pinth = _ida_allins.MIPS_pinth

MIPS_pceqb = _ida_allins.MIPS_pceqb

MIPS_pintoh = _ida_allins.MIPS_pintoh

MIPS_pmultw = _ida_allins.MIPS_pmultw

MIPS_pmultuw = _ida_allins.MIPS_pmultuw

MIPS_pcpyld = _ida_allins.MIPS_pcpyld

MIPS_pcpyud = _ida_allins.MIPS_pcpyud

MIPS_paddsw = _ida_allins.MIPS_paddsw

MIPS_pmaddh = _ida_allins.MIPS_pmaddh

MIPS_padduw = _ida_allins.MIPS_padduw

MIPS_psubsw = _ida_allins.MIPS_psubsw

MIPS_phmadh = _ida_allins.MIPS_phmadh

MIPS_psubuw = _ida_allins.MIPS_psubuw

MIPS_pextlw = _ida_allins.MIPS_pextlw

MIPS_pand = _ida_allins.MIPS_pand

MIPS_pextuw = _ida_allins.MIPS_pextuw

MIPS_por = _ida_allins.MIPS_por

MIPS_ppacw = _ida_allins.MIPS_ppacw

MIPS_pxor = _ida_allins.MIPS_pxor

MIPS_pnor = _ida_allins.MIPS_pnor

MIPS_paddsh = _ida_allins.MIPS_paddsh

MIPS_pmsubh = _ida_allins.MIPS_pmsubh

MIPS_padduh = _ida_allins.MIPS_padduh

MIPS_psubsh = _ida_allins.MIPS_psubsh

MIPS_phmsbh = _ida_allins.MIPS_phmsbh

MIPS_psubuh = _ida_allins.MIPS_psubuh

MIPS_pextlh = _ida_allins.MIPS_pextlh

MIPS_pextuh = _ida_allins.MIPS_pextuh

MIPS_ppach = _ida_allins.MIPS_ppach

MIPS_paddsb = _ida_allins.MIPS_paddsb

MIPS_paddub = _ida_allins.MIPS_paddub

MIPS_psubsb = _ida_allins.MIPS_psubsb

MIPS_psubub = _ida_allins.MIPS_psubub

MIPS_pextlb = _ida_allins.MIPS_pextlb

MIPS_pextub = _ida_allins.MIPS_pextub

MIPS_ppacb = _ida_allins.MIPS_ppacb

MIPS_qfsrv = _ida_allins.MIPS_qfsrv

MIPS_pmulth = _ida_allins.MIPS_pmulth

MIPS_pabsw = _ida_allins.MIPS_pabsw

MIPS_pabsh = _ida_allins.MIPS_pabsh

MIPS_pexoh = _ida_allins.MIPS_pexoh

MIPS_pexch = _ida_allins.MIPS_pexch

MIPS_prevh = _ida_allins.MIPS_prevh

MIPS_pcpyh = _ida_allins.MIPS_pcpyh

MIPS_pext5 = _ida_allins.MIPS_pext5

MIPS_pexow = _ida_allins.MIPS_pexow

MIPS_pexcw = _ida_allins.MIPS_pexcw

MIPS_ppac5 = _ida_allins.MIPS_ppac5

MIPS_prot3w = _ida_allins.MIPS_prot3w

MIPS_psllh = _ida_allins.MIPS_psllh

MIPS_psrlh = _ida_allins.MIPS_psrlh

MIPS_psrah = _ida_allins.MIPS_psrah

MIPS_psllw = _ida_allins.MIPS_psllw

MIPS_psrlw = _ida_allins.MIPS_psrlw

MIPS_psraw = _ida_allins.MIPS_psraw

MIPS_mfhi1 = _ida_allins.MIPS_mfhi1

MIPS_mflo1 = _ida_allins.MIPS_mflo1

MIPS_pmfhi = _ida_allins.MIPS_pmfhi

MIPS_pmflo = _ida_allins.MIPS_pmflo

MIPS_pmfhl = _ida_allins.MIPS_pmfhl

MIPS_lq = _ida_allins.MIPS_lq

MIPS_sq = _ida_allins.MIPS_sq

MIPS_lqc2 = _ida_allins.MIPS_lqc2

MIPS_sqc2 = _ida_allins.MIPS_sqc2

MIPS_madd_r5900 = _ida_allins.MIPS_madd_r5900

MIPS_maddu_r5900 = _ida_allins.MIPS_maddu_r5900

MIPS_R5900_last = _ida_allins.MIPS_R5900_last

MIPS_mult3 = _ida_allins.MIPS_mult3

MIPS_multu3 = _ida_allins.MIPS_multu3

MIPS_bteqz = _ida_allins.MIPS_bteqz

MIPS_btnez = _ida_allins.MIPS_btnez

MIPS_cmp = _ida_allins.MIPS_cmp

MIPS_cmpi = _ida_allins.MIPS_cmpi

MIPS_extend = _ida_allins.MIPS_extend

MIPS_move = _ida_allins.MIPS_move

MIPS_not = _ida_allins.MIPS_not

MIPS_dla = _ida_allins.MIPS_dla

MIPS_clo = _ida_allins.MIPS_clo

MIPS_clz = _ida_allins.MIPS_clz

MIPS_madd = _ida_allins.MIPS_madd

MIPS_maddu = _ida_allins.MIPS_maddu

MIPS_msub = _ida_allins.MIPS_msub

MIPS_msubu = _ida_allins.MIPS_msubu

MIPS_mul = _ida_allins.MIPS_mul

MIPS_sdbbp = _ida_allins.MIPS_sdbbp

MIPS_wait = _ida_allins.MIPS_wait

MIPS_alnv_ps = _ida_allins.MIPS_alnv_ps

MIPS_deret = _ida_allins.MIPS_deret

MIPS_di = _ida_allins.MIPS_di

MIPS_ehb = _ida_allins.MIPS_ehb

MIPS_ei = _ida_allins.MIPS_ei

MIPS_ext = _ida_allins.MIPS_ext

MIPS_fcvt_ps = _ida_allins.MIPS_fcvt_ps

MIPS_fcvt_s_pl = _ida_allins.MIPS_fcvt_s_pl

MIPS_fcvt_s_pu = _ida_allins.MIPS_fcvt_s_pu

MIPS_ins = _ida_allins.MIPS_ins

MIPS_jalr_hb = _ida_allins.MIPS_jalr_hb

MIPS_jr_hb = _ida_allins.MIPS_jr_hb

MIPS_luxc1 = _ida_allins.MIPS_luxc1

MIPS_madd_ps = _ida_allins.MIPS_madd_ps

MIPS_mfhc1 = _ida_allins.MIPS_mfhc1

MIPS_mfhc2 = _ida_allins.MIPS_mfhc2

MIPS_msub_ps = _ida_allins.MIPS_msub_ps

MIPS_mthc1 = _ida_allins.MIPS_mthc1

MIPS_mthc2 = _ida_allins.MIPS_mthc2

MIPS_nmadd_ps = _ida_allins.MIPS_nmadd_ps

MIPS_nmsub_ps = _ida_allins.MIPS_nmsub_ps

MIPS_pll = _ida_allins.MIPS_pll

MIPS_plu = _ida_allins.MIPS_plu

MIPS_pul = _ida_allins.MIPS_pul

MIPS_puu = _ida_allins.MIPS_puu

MIPS_rdhwr = _ida_allins.MIPS_rdhwr

MIPS_rdpgpr = _ida_allins.MIPS_rdpgpr

MIPS_rotr = _ida_allins.MIPS_rotr

MIPS_rotrv = _ida_allins.MIPS_rotrv

MIPS_seb = _ida_allins.MIPS_seb

MIPS_seh = _ida_allins.MIPS_seh

MIPS_suxc1 = _ida_allins.MIPS_suxc1

MIPS_synci = _ida_allins.MIPS_synci

MIPS_wrpgpr = _ida_allins.MIPS_wrpgpr

MIPS_wsbh = _ida_allins.MIPS_wsbh

MIPS_dmfc1 = _ida_allins.MIPS_dmfc1

MIPS_dmtc1 = _ida_allins.MIPS_dmtc1

MIPS_save = _ida_allins.MIPS_save

MIPS_restore = _ida_allins.MIPS_restore

MIPS_jalrc = _ida_allins.MIPS_jalrc

MIPS_jrc = _ida_allins.MIPS_jrc

MIPS_sew = _ida_allins.MIPS_sew

MIPS_zeb = _ida_allins.MIPS_zeb

MIPS_zeh = _ida_allins.MIPS_zeh

MIPS_zew = _ida_allins.MIPS_zew

MIPS_ssnop = _ida_allins.MIPS_ssnop

MIPS_li_s = _ida_allins.MIPS_li_s

MIPS_li_d = _ida_allins.MIPS_li_d

MIPS_dneg = _ida_allins.MIPS_dneg

MIPS_dnegu = _ida_allins.MIPS_dnegu

MIPS_pause = _ida_allins.MIPS_pause

MIPS_dclo = _ida_allins.MIPS_dclo

MIPS_dclz = _ida_allins.MIPS_dclz

MIPS_dext = _ida_allins.MIPS_dext

MIPS_dextm = _ida_allins.MIPS_dextm

MIPS_dextu = _ida_allins.MIPS_dextu

MIPS_dins = _ida_allins.MIPS_dins

MIPS_dinsm = _ida_allins.MIPS_dinsm

MIPS_dinsu = _ida_allins.MIPS_dinsu

MIPS_dmfc2 = _ida_allins.MIPS_dmfc2

MIPS_dmtc2 = _ida_allins.MIPS_dmtc2

MIPS_drotr = _ida_allins.MIPS_drotr

MIPS_drotr32 = _ida_allins.MIPS_drotr32

MIPS_drotrv = _ida_allins.MIPS_drotrv

MIPS_dsbh = _ida_allins.MIPS_dsbh

MIPS_dshd = _ida_allins.MIPS_dshd

MIPS_baddu = _ida_allins.MIPS_baddu

MIPS_bbit0 = _ida_allins.MIPS_bbit0

MIPS_bbit032 = _ida_allins.MIPS_bbit032

MIPS_bbit1 = _ida_allins.MIPS_bbit1

MIPS_bbit132 = _ida_allins.MIPS_bbit132

MIPS_cins = _ida_allins.MIPS_cins

MIPS_cins32 = _ida_allins.MIPS_cins32

MIPS_dmul = _ida_allins.MIPS_dmul

MIPS_dpop = _ida_allins.MIPS_dpop

MIPS_exts = _ida_allins.MIPS_exts

MIPS_exts32 = _ida_allins.MIPS_exts32

MIPS_mtm0 = _ida_allins.MIPS_mtm0

MIPS_mtm1 = _ida_allins.MIPS_mtm1

MIPS_mtm2 = _ida_allins.MIPS_mtm2

MIPS_mtp0 = _ida_allins.MIPS_mtp0

MIPS_mtp1 = _ida_allins.MIPS_mtp1

MIPS_mtp2 = _ida_allins.MIPS_mtp2

MIPS_pop = _ida_allins.MIPS_pop

MIPS_saa = _ida_allins.MIPS_saa

MIPS_saad = _ida_allins.MIPS_saad

MIPS_seq = _ida_allins.MIPS_seq

MIPS_seqi = _ida_allins.MIPS_seqi

MIPS_sne = _ida_allins.MIPS_sne

MIPS_snei = _ida_allins.MIPS_snei

MIPS_synciobdma = _ida_allins.MIPS_synciobdma

MIPS_syncs = _ida_allins.MIPS_syncs

MIPS_syncw = _ida_allins.MIPS_syncw

MIPS_syncws = _ida_allins.MIPS_syncws

MIPS_uld = _ida_allins.MIPS_uld

MIPS_ulw = _ida_allins.MIPS_ulw

MIPS_usd = _ida_allins.MIPS_usd

MIPS_usw = _ida_allins.MIPS_usw

MIPS_v3mulu = _ida_allins.MIPS_v3mulu

MIPS_vmm0 = _ida_allins.MIPS_vmm0

MIPS_vmulu_cn = _ida_allins.MIPS_vmulu_cn

MIPS_dbreak = _ida_allins.MIPS_dbreak

MIPS_dret = _ida_allins.MIPS_dret

MIPS_mfdr = _ida_allins.MIPS_mfdr

MIPS_mtdr = _ida_allins.MIPS_mtdr

PSP_bitrev = _ida_allins.PSP_bitrev

PSP_max = _ida_allins.PSP_max

PSP_min = _ida_allins.PSP_min

PSP_mfic = _ida_allins.PSP_mfic

PSP_mtic = _ida_allins.PSP_mtic

PSP_wsbw = _ida_allins.PSP_wsbw

PSP_sleep = _ida_allins.PSP_sleep

PSP_lv = _ida_allins.PSP_lv

PSP_lvl = _ida_allins.PSP_lvl

PSP_lvr = _ida_allins.PSP_lvr

PSP_sv = _ida_allins.PSP_sv

PSP_svl = _ida_allins.PSP_svl

PSP_svr = _ida_allins.PSP_svr

PSP_mfv = _ida_allins.PSP_mfv

PSP_mtv = _ida_allins.PSP_mtv

PSP_mfvc = _ida_allins.PSP_mfvc

PSP_mtvc = _ida_allins.PSP_mtvc

PSP_bvf = _ida_allins.PSP_bvf

PSP_bvt = _ida_allins.PSP_bvt

PSP_bvfl = _ida_allins.PSP_bvfl

PSP_bvtl = _ida_allins.PSP_bvtl

PSP_vnop = _ida_allins.PSP_vnop

PSP_vflush = _ida_allins.PSP_vflush

PSP_vsync = _ida_allins.PSP_vsync

PSP_vabs = _ida_allins.PSP_vabs

PSP_vadd = _ida_allins.PSP_vadd

PSP_vasin = _ida_allins.PSP_vasin

PSP_vavg = _ida_allins.PSP_vavg

PSP_vbfy1 = _ida_allins.PSP_vbfy1

PSP_vbfy2 = _ida_allins.PSP_vbfy2

PSP_vc2i = _ida_allins.PSP_vc2i

PSP_vcmovf = _ida_allins.PSP_vcmovf

PSP_vcmovt = _ida_allins.PSP_vcmovt

PSP_vcmp = _ida_allins.PSP_vcmp

PSP_vcos = _ida_allins.PSP_vcos

PSP_vcrs = _ida_allins.PSP_vcrs

PSP_vcrsp = _ida_allins.PSP_vcrsp

PSP_vcst = _ida_allins.PSP_vcst

PSP_vdet = _ida_allins.PSP_vdet

PSP_vdiv = _ida_allins.PSP_vdiv

PSP_vdot = _ida_allins.PSP_vdot

PSP_vexp2 = _ida_allins.PSP_vexp2

PSP_vf2h = _ida_allins.PSP_vf2h

PSP_vf2id = _ida_allins.PSP_vf2id

PSP_vf2in = _ida_allins.PSP_vf2in

PSP_vf2iu = _ida_allins.PSP_vf2iu

PSP_vf2iz = _ida_allins.PSP_vf2iz

PSP_vfad = _ida_allins.PSP_vfad

PSP_vfim = _ida_allins.PSP_vfim

PSP_vh2f = _ida_allins.PSP_vh2f

PSP_vhdp = _ida_allins.PSP_vhdp

PSP_vhtfm2 = _ida_allins.PSP_vhtfm2

PSP_vhtfm3 = _ida_allins.PSP_vhtfm3

PSP_vhtfm4 = _ida_allins.PSP_vhtfm4

PSP_vi2c = _ida_allins.PSP_vi2c

PSP_vi2f = _ida_allins.PSP_vi2f

PSP_vi2s = _ida_allins.PSP_vi2s

PSP_vi2uc = _ida_allins.PSP_vi2uc

PSP_vi2us = _ida_allins.PSP_vi2us

PSP_vidt = _ida_allins.PSP_vidt

PSP_viim = _ida_allins.PSP_viim

PSP_vlgb = _ida_allins.PSP_vlgb

PSP_vlog2 = _ida_allins.PSP_vlog2

PSP_vmax = _ida_allins.PSP_vmax

PSP_vmfvc = _ida_allins.PSP_vmfvc

PSP_vmidt = _ida_allins.PSP_vmidt

PSP_vmin = _ida_allins.PSP_vmin

PSP_vmmov = _ida_allins.PSP_vmmov

PSP_vmmul = _ida_allins.PSP_vmmul

PSP_vmone = _ida_allins.PSP_vmone

PSP_vmov = _ida_allins.PSP_vmov

PSP_vmscl = _ida_allins.PSP_vmscl

PSP_vmtvc = _ida_allins.PSP_vmtvc

PSP_vmul = _ida_allins.PSP_vmul

PSP_vmzero = _ida_allins.PSP_vmzero

PSP_vneg = _ida_allins.PSP_vneg

PSP_vnrcp = _ida_allins.PSP_vnrcp

PSP_vnsin = _ida_allins.PSP_vnsin

PSP_vocp = _ida_allins.PSP_vocp

PSP_vone = _ida_allins.PSP_vone

PSP_vpfxd = _ida_allins.PSP_vpfxd

PSP_vpfxs = _ida_allins.PSP_vpfxs

PSP_vpfxt = _ida_allins.PSP_vpfxt

PSP_vqmul = _ida_allins.PSP_vqmul

PSP_vrcp = _ida_allins.PSP_vrcp

PSP_vrexp2 = _ida_allins.PSP_vrexp2

PSP_vrndf1 = _ida_allins.PSP_vrndf1

PSP_vrndf2 = _ida_allins.PSP_vrndf2

PSP_vrndi = _ida_allins.PSP_vrndi

PSP_vrnds = _ida_allins.PSP_vrnds

PSP_vrot = _ida_allins.PSP_vrot

PSP_vrsq = _ida_allins.PSP_vrsq

PSP_vs2i = _ida_allins.PSP_vs2i

PSP_vsat0 = _ida_allins.PSP_vsat0

PSP_vsat1 = _ida_allins.PSP_vsat1

PSP_vsbn = _ida_allins.PSP_vsbn

PSP_vsbz = _ida_allins.PSP_vsbz

PSP_vscl = _ida_allins.PSP_vscl

PSP_vscmp = _ida_allins.PSP_vscmp

PSP_vsge = _ida_allins.PSP_vsge

PSP_vsgn = _ida_allins.PSP_vsgn

PSP_vsin = _ida_allins.PSP_vsin

PSP_vslt = _ida_allins.PSP_vslt

PSP_vsocp = _ida_allins.PSP_vsocp

PSP_vsqrt = _ida_allins.PSP_vsqrt

PSP_vsrt1 = _ida_allins.PSP_vsrt1

PSP_vsrt2 = _ida_allins.PSP_vsrt2

PSP_vsrt3 = _ida_allins.PSP_vsrt3

PSP_vsrt4 = _ida_allins.PSP_vsrt4

PSP_vsub = _ida_allins.PSP_vsub

PSP_vt4444 = _ida_allins.PSP_vt4444

PSP_vt5551 = _ida_allins.PSP_vt5551

PSP_vt5650 = _ida_allins.PSP_vt5650

PSP_vtfm2 = _ida_allins.PSP_vtfm2

PSP_vtfm3 = _ida_allins.PSP_vtfm3

PSP_vtfm4 = _ida_allins.PSP_vtfm4

PSP_vuc2i = _ida_allins.PSP_vuc2i

PSP_vus2i = _ida_allins.PSP_vus2i

PSP_vwbn = _ida_allins.PSP_vwbn

PSP_vzero = _ida_allins.PSP_vzero

PSP_mfvme = _ida_allins.PSP_mfvme

PSP_mtvme = _ida_allins.PSP_mtvme

MIPS_ac0iu = _ida_allins.MIPS_ac0iu

MIPS_bs1f = _ida_allins.MIPS_bs1f

MIPS_bfins = _ida_allins.MIPS_bfins

MIPS_addmiu = _ida_allins.MIPS_addmiu

MIPS_sadd = _ida_allins.MIPS_sadd

MIPS_ssub = _ida_allins.MIPS_ssub

MIPS_btst = _ida_allins.MIPS_btst

MIPS_bclr = _ida_allins.MIPS_bclr

MIPS_bset = _ida_allins.MIPS_bset

MIPS_bins = _ida_allins.MIPS_bins

MIPS_bext = _ida_allins.MIPS_bext

MIPS_dive = _ida_allins.MIPS_dive

MIPS_diveu = _ida_allins.MIPS_diveu

MIPS_min = _ida_allins.MIPS_min

MIPS_max = _ida_allins.MIPS_max

MIPS_madd3 = _ida_allins.MIPS_madd3

MIPS_maddu3 = _ida_allins.MIPS_maddu3

MIPS_msub3 = _ida_allins.MIPS_msub3

MIPS_msubu3 = _ida_allins.MIPS_msubu3

MIPS_dvpe = _ida_allins.MIPS_dvpe

MIPS_evpe = _ida_allins.MIPS_evpe

MIPS_dmt = _ida_allins.MIPS_dmt

MIPS_emt = _ida_allins.MIPS_emt

MIPS_fork = _ida_allins.MIPS_fork

MIPS_yield = _ida_allins.MIPS_yield

MIPS_mftr = _ida_allins.MIPS_mftr

MIPS_mftc0 = _ida_allins.MIPS_mftc0

MIPS_mftlo = _ida_allins.MIPS_mftlo

MIPS_mfthi = _ida_allins.MIPS_mfthi

MIPS_mftacx = _ida_allins.MIPS_mftacx

MIPS_mftdsp = _ida_allins.MIPS_mftdsp

MIPS_mfthc1 = _ida_allins.MIPS_mfthc1

MIPS_mftc1 = _ida_allins.MIPS_mftc1

MIPS_cftc1 = _ida_allins.MIPS_cftc1

MIPS_mfthc2 = _ida_allins.MIPS_mfthc2

MIPS_mftc2 = _ida_allins.MIPS_mftc2

MIPS_cftc2 = _ida_allins.MIPS_cftc2

MIPS_mftgpr = _ida_allins.MIPS_mftgpr

MIPS_mttr = _ida_allins.MIPS_mttr

MIPS_mttc0 = _ida_allins.MIPS_mttc0

MIPS_mttlo = _ida_allins.MIPS_mttlo

MIPS_mtthi = _ida_allins.MIPS_mtthi

MIPS_mttacx = _ida_allins.MIPS_mttacx

MIPS_mttdsp = _ida_allins.MIPS_mttdsp

MIPS_mtthc1 = _ida_allins.MIPS_mtthc1

MIPS_mttc1 = _ida_allins.MIPS_mttc1

MIPS_cttc1 = _ida_allins.MIPS_cttc1

MIPS_mtthc2 = _ida_allins.MIPS_mtthc2

MIPS_mttc2 = _ida_allins.MIPS_mttc2

MIPS_cttc2 = _ida_allins.MIPS_cttc2

MIPS_mttgpr = _ida_allins.MIPS_mttgpr

MIPS_faddr = _ida_allins.MIPS_faddr

MIPS_bc1any2f = _ida_allins.MIPS_bc1any2f

MIPS_bc1any2t = _ida_allins.MIPS_bc1any2t

MIPS_bc1any4f = _ida_allins.MIPS_bc1any4f

MIPS_bc1any4t = _ida_allins.MIPS_bc1any4t

MIPS_fcabs_f = _ida_allins.MIPS_fcabs_f

MIPS_fcabs_un = _ida_allins.MIPS_fcabs_un

MIPS_fcabs_eq = _ida_allins.MIPS_fcabs_eq

MIPS_fcabs_ueq = _ida_allins.MIPS_fcabs_ueq

MIPS_fcabs_olt = _ida_allins.MIPS_fcabs_olt

MIPS_fcabs_ult = _ida_allins.MIPS_fcabs_ult

MIPS_fcabs_ole = _ida_allins.MIPS_fcabs_ole

MIPS_fcabs_ule = _ida_allins.MIPS_fcabs_ule

MIPS_fcabs_sf = _ida_allins.MIPS_fcabs_sf

MIPS_fcabs_ngle = _ida_allins.MIPS_fcabs_ngle

MIPS_fcabs_seq = _ida_allins.MIPS_fcabs_seq

MIPS_fcabs_ngl = _ida_allins.MIPS_fcabs_ngl

MIPS_fcabs_lt = _ida_allins.MIPS_fcabs_lt

MIPS_fcabs_nge = _ida_allins.MIPS_fcabs_nge

MIPS_fcabs_le = _ida_allins.MIPS_fcabs_le

MIPS_fcabs_ngt = _ida_allins.MIPS_fcabs_ngt

MIPS_fcvt_pw_ps = _ida_allins.MIPS_fcvt_pw_ps

MIPS_fcvt_ps_pw = _ida_allins.MIPS_fcvt_ps_pw

MIPS_fmulr = _ida_allins.MIPS_fmulr

MIPS_frecip1 = _ida_allins.MIPS_frecip1

MIPS_frecip2 = _ida_allins.MIPS_frecip2

MIPS_frsqrt1 = _ida_allins.MIPS_frsqrt1

MIPS_frsqrt2 = _ida_allins.MIPS_frsqrt2

MIPS_lwxs = _ida_allins.MIPS_lwxs

MIPS_maddp = _ida_allins.MIPS_maddp

MIPS_mflhxu = _ida_allins.MIPS_mflhxu

MIPS_mtlhx = _ida_allins.MIPS_mtlhx

MIPS_multp = _ida_allins.MIPS_multp

MIPS_pperm = _ida_allins.MIPS_pperm

MIPS_jals = _ida_allins.MIPS_jals

MIPS_lwp = _ida_allins.MIPS_lwp

MIPS_ldp = _ida_allins.MIPS_ldp

MIPS_lwm = _ida_allins.MIPS_lwm

MIPS_ldm = _ida_allins.MIPS_ldm

MIPS_swp = _ida_allins.MIPS_swp

MIPS_sdp = _ida_allins.MIPS_sdp

MIPS_swm = _ida_allins.MIPS_swm

MIPS_sdm = _ida_allins.MIPS_sdm

MIPS_bnezc = _ida_allins.MIPS_bnezc

MIPS_bltzals = _ida_allins.MIPS_bltzals

MIPS_beqzc = _ida_allins.MIPS_beqzc

MIPS_bgezals = _ida_allins.MIPS_bgezals

MIPS_jraddiusp = _ida_allins.MIPS_jraddiusp

MIPS_jalrs = _ida_allins.MIPS_jalrs

MIPS_jalrs_hb = _ida_allins.MIPS_jalrs_hb

MIPS_movep = _ida_allins.MIPS_movep

MIPS_dli = _ida_allins.MIPS_dli

MIPS_insv = _ida_allins.MIPS_insv

MIPS_dinsv = _ida_allins.MIPS_dinsv

MIPS_bposge32 = _ida_allins.MIPS_bposge32

MIPS_bposge64 = _ida_allins.MIPS_bposge64

MIPS_addu_qb = _ida_allins.MIPS_addu_qb

MIPS_addu_ph = _ida_allins.MIPS_addu_ph

MIPS_addsc = _ida_allins.MIPS_addsc

MIPS_subu_qb = _ida_allins.MIPS_subu_qb

MIPS_subu_ph = _ida_allins.MIPS_subu_ph

MIPS_addwc = _ida_allins.MIPS_addwc

MIPS_addq_ph = _ida_allins.MIPS_addq_ph

MIPS_modsub = _ida_allins.MIPS_modsub

MIPS_subq_ph = _ida_allins.MIPS_subq_ph

MIPS_addu_s_qb = _ida_allins.MIPS_addu_s_qb

MIPS_addu_s_ph = _ida_allins.MIPS_addu_s_ph

MIPS_raddu_w_qb = _ida_allins.MIPS_raddu_w_qb

MIPS_muleq_s_w_phl = _ida_allins.MIPS_muleq_s_w_phl

MIPS_subu_s_qb = _ida_allins.MIPS_subu_s_qb

MIPS_subu_s_ph = _ida_allins.MIPS_subu_s_ph

MIPS_muleq_s_w_phr = _ida_allins.MIPS_muleq_s_w_phr

MIPS_muleu_s_ph_qbl = _ida_allins.MIPS_muleu_s_ph_qbl

MIPS_addq_s_ph = _ida_allins.MIPS_addq_s_ph

MIPS_addq_s_w = _ida_allins.MIPS_addq_s_w

MIPS_mulq_s_ph = _ida_allins.MIPS_mulq_s_ph

MIPS_muleu_s_ph_qbr = _ida_allins.MIPS_muleu_s_ph_qbr

MIPS_subq_s_ph = _ida_allins.MIPS_subq_s_ph

MIPS_subq_s_w = _ida_allins.MIPS_subq_s_w

MIPS_mulq_rs_ph = _ida_allins.MIPS_mulq_rs_ph

MIPS_addu_ob = _ida_allins.MIPS_addu_ob

MIPS_subu_ob = _ida_allins.MIPS_subu_ob

MIPS_addq_qh = _ida_allins.MIPS_addq_qh

MIPS_addq_pw = _ida_allins.MIPS_addq_pw

MIPS_subq_qh = _ida_allins.MIPS_subq_qh

MIPS_subq_pw = _ida_allins.MIPS_subq_pw

MIPS_addu_s_ob = _ida_allins.MIPS_addu_s_ob

MIPS_raddu_l_ob = _ida_allins.MIPS_raddu_l_ob

MIPS_muleq_s_pw_qhl = _ida_allins.MIPS_muleq_s_pw_qhl

MIPS_subu_s_ob = _ida_allins.MIPS_subu_s_ob

MIPS_muleq_s_pw_qhr = _ida_allins.MIPS_muleq_s_pw_qhr

MIPS_muleu_s_qh_obl = _ida_allins.MIPS_muleu_s_qh_obl

MIPS_addq_s_qh = _ida_allins.MIPS_addq_s_qh

MIPS_addq_s_pw = _ida_allins.MIPS_addq_s_pw

MIPS_muleu_s_qh_obr = _ida_allins.MIPS_muleu_s_qh_obr

MIPS_subq_s_qh = _ida_allins.MIPS_subq_s_qh

MIPS_subq_s_pw = _ida_allins.MIPS_subq_s_pw

MIPS_mulq_rs_qh = _ida_allins.MIPS_mulq_rs_qh

MIPS_cmpu_eq_qb = _ida_allins.MIPS_cmpu_eq_qb

MIPS_cmp_eq_ph = _ida_allins.MIPS_cmp_eq_ph

MIPS_cmpgdu_eq_qb = _ida_allins.MIPS_cmpgdu_eq_qb

MIPS_cmpu_lt_qb = _ida_allins.MIPS_cmpu_lt_qb

MIPS_cmp_lt_ph = _ida_allins.MIPS_cmp_lt_ph

MIPS_cmpgdu_lt_qb = _ida_allins.MIPS_cmpgdu_lt_qb

MIPS_cmpu_le_qb = _ida_allins.MIPS_cmpu_le_qb

MIPS_cmp_le_ph = _ida_allins.MIPS_cmp_le_ph

MIPS_cmpgdu_le_qb = _ida_allins.MIPS_cmpgdu_le_qb

MIPS_pick_qb = _ida_allins.MIPS_pick_qb

MIPS_pick_ph = _ida_allins.MIPS_pick_ph

MIPS_cmpgu_eq_qb = _ida_allins.MIPS_cmpgu_eq_qb

MIPS_precrq_qb_ph = _ida_allins.MIPS_precrq_qb_ph

MIPS_precrq_ph_w = _ida_allins.MIPS_precrq_ph_w

MIPS_cmpgu_lt_qb = _ida_allins.MIPS_cmpgu_lt_qb

MIPS_precr_qb_ph = _ida_allins.MIPS_precr_qb_ph

MIPS_precrq_rs_ph_w = _ida_allins.MIPS_precrq_rs_ph_w

MIPS_cmpgu_le_qb = _ida_allins.MIPS_cmpgu_le_qb

MIPS_packrl_ph = _ida_allins.MIPS_packrl_ph

MIPS_precr_sra_ph_w = _ida_allins.MIPS_precr_sra_ph_w

MIPS_precrqu_s_qb_ph = _ida_allins.MIPS_precrqu_s_qb_ph

MIPS_precr_sra_r_ph_w = _ida_allins.MIPS_precr_sra_r_ph_w

MIPS_cmpu_eq_ob = _ida_allins.MIPS_cmpu_eq_ob

MIPS_cmp_eq_qh = _ida_allins.MIPS_cmp_eq_qh

MIPS_cmp_eq_pw = _ida_allins.MIPS_cmp_eq_pw

MIPS_cmpu_lt_ob = _ida_allins.MIPS_cmpu_lt_ob

MIPS_cmp_lt_qh = _ida_allins.MIPS_cmp_lt_qh

MIPS_cmp_lt_pw = _ida_allins.MIPS_cmp_lt_pw

MIPS_cmpu_le_ob = _ida_allins.MIPS_cmpu_le_ob

MIPS_cmp_le_qh = _ida_allins.MIPS_cmp_le_qh

MIPS_cmp_le_pw = _ida_allins.MIPS_cmp_le_pw

MIPS_pick_ob = _ida_allins.MIPS_pick_ob

MIPS_pick_qh = _ida_allins.MIPS_pick_qh

MIPS_pick_pw = _ida_allins.MIPS_pick_pw

MIPS_cmpgu_eq_ob = _ida_allins.MIPS_cmpgu_eq_ob

MIPS_precrq_ob_qh = _ida_allins.MIPS_precrq_ob_qh

MIPS_precrq_qh_pw = _ida_allins.MIPS_precrq_qh_pw

MIPS_precrq_pw_l = _ida_allins.MIPS_precrq_pw_l

MIPS_cmpgu_lt_ob = _ida_allins.MIPS_cmpgu_lt_ob

MIPS_precrq_rs_qh_pw = _ida_allins.MIPS_precrq_rs_qh_pw

MIPS_cmpgu_le_ob = _ida_allins.MIPS_cmpgu_le_ob

MIPS_packrl_pw = _ida_allins.MIPS_packrl_pw

MIPS_precrqu_s_ob_qh = _ida_allins.MIPS_precrqu_s_ob_qh

MIPS_absq_s_qb = _ida_allins.MIPS_absq_s_qb

MIPS_absq_s_ph = _ida_allins.MIPS_absq_s_ph

MIPS_absq_s_w = _ida_allins.MIPS_absq_s_w

MIPS_repl_qb = _ida_allins.MIPS_repl_qb

MIPS_repl_ph = _ida_allins.MIPS_repl_ph

MIPS_replv_qb = _ida_allins.MIPS_replv_qb

MIPS_replv_ph = _ida_allins.MIPS_replv_ph

MIPS_bitrev = _ida_allins.MIPS_bitrev

MIPS_precequ_ph_qbl = _ida_allins.MIPS_precequ_ph_qbl

MIPS_preceq_w_phl = _ida_allins.MIPS_preceq_w_phl

MIPS_preceu_ph_qbl = _ida_allins.MIPS_preceu_ph_qbl

MIPS_precequ_ph_qbr = _ida_allins.MIPS_precequ_ph_qbr

MIPS_preceq_w_phr = _ida_allins.MIPS_preceq_w_phr

MIPS_preceu_ph_qbr = _ida_allins.MIPS_preceu_ph_qbr

MIPS_precequ_ph_qbla = _ida_allins.MIPS_precequ_ph_qbla

MIPS_preceu_ph_qbla = _ida_allins.MIPS_preceu_ph_qbla

MIPS_precequ_ph_qbra = _ida_allins.MIPS_precequ_ph_qbra

MIPS_preceu_ph_qbra = _ida_allins.MIPS_preceu_ph_qbra

MIPS_absq_s_qh = _ida_allins.MIPS_absq_s_qh

MIPS_absq_s_pw = _ida_allins.MIPS_absq_s_pw

MIPS_repl_ob = _ida_allins.MIPS_repl_ob

MIPS_repl_qh = _ida_allins.MIPS_repl_qh

MIPS_repl_pw = _ida_allins.MIPS_repl_pw

MIPS_replv_ob = _ida_allins.MIPS_replv_ob

MIPS_replv_qh = _ida_allins.MIPS_replv_qh

MIPS_replv_pw = _ida_allins.MIPS_replv_pw

MIPS_precequ_pw_qhl = _ida_allins.MIPS_precequ_pw_qhl

MIPS_preceq_pw_qhl = _ida_allins.MIPS_preceq_pw_qhl

MIPS_preceq_s_l_pwl = _ida_allins.MIPS_preceq_s_l_pwl

MIPS_preceu_qh_obl = _ida_allins.MIPS_preceu_qh_obl

MIPS_precequ_pw_qhr = _ida_allins.MIPS_precequ_pw_qhr

MIPS_preceq_pw_qhr = _ida_allins.MIPS_preceq_pw_qhr

MIPS_preceq_s_l_pwr = _ida_allins.MIPS_preceq_s_l_pwr

MIPS_preceu_qh_obr = _ida_allins.MIPS_preceu_qh_obr

MIPS_precequ_pw_qhla = _ida_allins.MIPS_precequ_pw_qhla

MIPS_preceq_pw_qhla = _ida_allins.MIPS_preceq_pw_qhla

MIPS_preceu_qh_obla = _ida_allins.MIPS_preceu_qh_obla

MIPS_precequ_pw_qhra = _ida_allins.MIPS_precequ_pw_qhra

MIPS_preceq_pw_qhra = _ida_allins.MIPS_preceq_pw_qhra

MIPS_preceu_qh_obra = _ida_allins.MIPS_preceu_qh_obra

MIPS_shll_qb = _ida_allins.MIPS_shll_qb

MIPS_shll_ph = _ida_allins.MIPS_shll_ph

MIPS_shrl_qb = _ida_allins.MIPS_shrl_qb

MIPS_shra_ph = _ida_allins.MIPS_shra_ph

MIPS_shrl_ph = _ida_allins.MIPS_shrl_ph

MIPS_shllv_qb = _ida_allins.MIPS_shllv_qb

MIPS_shllv_ph = _ida_allins.MIPS_shllv_ph

MIPS_shrlv_qb = _ida_allins.MIPS_shrlv_qb

MIPS_shrav_ph = _ida_allins.MIPS_shrav_ph

MIPS_shrlv_ph = _ida_allins.MIPS_shrlv_ph

MIPS_shra_qb = _ida_allins.MIPS_shra_qb

MIPS_shll_s_ph = _ida_allins.MIPS_shll_s_ph

MIPS_shll_s_w = _ida_allins.MIPS_shll_s_w

MIPS_shra_r_qb = _ida_allins.MIPS_shra_r_qb

MIPS_shra_r_ph = _ida_allins.MIPS_shra_r_ph

MIPS_shra_r_w = _ida_allins.MIPS_shra_r_w

MIPS_shrav_qb = _ida_allins.MIPS_shrav_qb

MIPS_shllv_s_ph = _ida_allins.MIPS_shllv_s_ph

MIPS_shllv_s_w = _ida_allins.MIPS_shllv_s_w

MIPS_shrav_r_qb = _ida_allins.MIPS_shrav_r_qb

MIPS_shrav_r_ph = _ida_allins.MIPS_shrav_r_ph

MIPS_shrav_r_w = _ida_allins.MIPS_shrav_r_w

MIPS_shll_ob = _ida_allins.MIPS_shll_ob

MIPS_shll_qh = _ida_allins.MIPS_shll_qh

MIPS_shll_pw = _ida_allins.MIPS_shll_pw

MIPS_shrl_ob = _ida_allins.MIPS_shrl_ob

MIPS_shra_qh = _ida_allins.MIPS_shra_qh

MIPS_shra_pw = _ida_allins.MIPS_shra_pw

MIPS_shllv_ob = _ida_allins.MIPS_shllv_ob

MIPS_shllv_qh = _ida_allins.MIPS_shllv_qh

MIPS_shllv_pw = _ida_allins.MIPS_shllv_pw

MIPS_shrlv_ob = _ida_allins.MIPS_shrlv_ob

MIPS_shrav_qh = _ida_allins.MIPS_shrav_qh

MIPS_shrav_pw = _ida_allins.MIPS_shrav_pw

MIPS_shll_s_qh = _ida_allins.MIPS_shll_s_qh

MIPS_shll_s_pw = _ida_allins.MIPS_shll_s_pw

MIPS_shra_r_qh = _ida_allins.MIPS_shra_r_qh

MIPS_shra_r_pw = _ida_allins.MIPS_shra_r_pw

MIPS_shllv_s_qh = _ida_allins.MIPS_shllv_s_qh

MIPS_shllv_s_pw = _ida_allins.MIPS_shllv_s_pw

MIPS_shrav_r_qh = _ida_allins.MIPS_shrav_r_qh

MIPS_shrav_r_pw = _ida_allins.MIPS_shrav_r_pw

MIPS_lwx = _ida_allins.MIPS_lwx

MIPS_ldx = _ida_allins.MIPS_ldx

MIPS_lhx = _ida_allins.MIPS_lhx

MIPS_lbux = _ida_allins.MIPS_lbux

MIPS_dpa_w_ph = _ida_allins.MIPS_dpa_w_ph

MIPS_dpax_w_ph = _ida_allins.MIPS_dpax_w_ph

MIPS_maq_sa_w_phl = _ida_allins.MIPS_maq_sa_w_phl

MIPS_dpaqx_s_w_ph = _ida_allins.MIPS_dpaqx_s_w_ph

MIPS_dps_w_ph = _ida_allins.MIPS_dps_w_ph

MIPS_dpsx_w_ph = _ida_allins.MIPS_dpsx_w_ph

MIPS_dpsqx_s_w_ph = _ida_allins.MIPS_dpsqx_s_w_ph

MIPS_mulsa_w_ph = _ida_allins.MIPS_mulsa_w_ph

MIPS_maq_sa_w_phr = _ida_allins.MIPS_maq_sa_w_phr

MIPS_dpaqx_sa_w_ph = _ida_allins.MIPS_dpaqx_sa_w_ph

MIPS_dpau_h_qbl = _ida_allins.MIPS_dpau_h_qbl

MIPS_dpsu_h_qbl = _ida_allins.MIPS_dpsu_h_qbl

MIPS_dpsqx_sa_w_ph = _ida_allins.MIPS_dpsqx_sa_w_ph

MIPS_dpaq_s_w_ph = _ida_allins.MIPS_dpaq_s_w_ph

MIPS_dpaq_sa_l_w = _ida_allins.MIPS_dpaq_sa_l_w

MIPS_maq_s_w_phl = _ida_allins.MIPS_maq_s_w_phl

MIPS_dpsq_s_w_ph = _ida_allins.MIPS_dpsq_s_w_ph

MIPS_dpsq_sa_l_w = _ida_allins.MIPS_dpsq_sa_l_w

MIPS_mulsaq_s_w_ph = _ida_allins.MIPS_mulsaq_s_w_ph

MIPS_maq_s_w_phr = _ida_allins.MIPS_maq_s_w_phr

MIPS_dpau_h_qbr = _ida_allins.MIPS_dpau_h_qbr

MIPS_dpsu_h_qbr = _ida_allins.MIPS_dpsu_h_qbr

MIPS_maq_sa_w_qhll = _ida_allins.MIPS_maq_sa_w_qhll

MIPS_maq_sa_w_qhlr = _ida_allins.MIPS_maq_sa_w_qhlr

MIPS_dmadd = _ida_allins.MIPS_dmadd

MIPS_dmsub = _ida_allins.MIPS_dmsub

MIPS_maq_sa_w_qhrl = _ida_allins.MIPS_maq_sa_w_qhrl

MIPS_dpau_h_obl = _ida_allins.MIPS_dpau_h_obl

MIPS_dpsu_h_obl = _ida_allins.MIPS_dpsu_h_obl

MIPS_maq_sa_w_qhrr = _ida_allins.MIPS_maq_sa_w_qhrr

MIPS_dpaq_s_w_qh = _ida_allins.MIPS_dpaq_s_w_qh

MIPS_dpaq_sa_l_pw = _ida_allins.MIPS_dpaq_sa_l_pw

MIPS_maq_s_w_qhll = _ida_allins.MIPS_maq_s_w_qhll

MIPS_maq_s_l_pwl = _ida_allins.MIPS_maq_s_l_pwl

MIPS_dpsq_s_w_qh = _ida_allins.MIPS_dpsq_s_w_qh

MIPS_dpsq_sa_l_pw = _ida_allins.MIPS_dpsq_sa_l_pw

MIPS_maq_s_w_qhlr = _ida_allins.MIPS_maq_s_w_qhlr

MIPS_dmaddu = _ida_allins.MIPS_dmaddu

MIPS_mulsaq_s_w_qh = _ida_allins.MIPS_mulsaq_s_w_qh

MIPS_mulsaq_s_l_pw = _ida_allins.MIPS_mulsaq_s_l_pw

MIPS_maq_s_w_qhrl = _ida_allins.MIPS_maq_s_w_qhrl

MIPS_maq_s_l_pwr = _ida_allins.MIPS_maq_s_l_pwr

MIPS_dpau_h_obr = _ida_allins.MIPS_dpau_h_obr

MIPS_dpsu_h_obr = _ida_allins.MIPS_dpsu_h_obr

MIPS_maq_s_w_qhrr = _ida_allins.MIPS_maq_s_w_qhrr

MIPS_dmsubu = _ida_allins.MIPS_dmsubu

MIPS_extr_w = _ida_allins.MIPS_extr_w

MIPS_extrv_w = _ida_allins.MIPS_extrv_w

MIPS_extp = _ida_allins.MIPS_extp

MIPS_extpdp = _ida_allins.MIPS_extpdp

MIPS_rddsp = _ida_allins.MIPS_rddsp

MIPS_shilo = _ida_allins.MIPS_shilo

MIPS_extpv = _ida_allins.MIPS_extpv

MIPS_extpdpv = _ida_allins.MIPS_extpdpv

MIPS_wrdsp = _ida_allins.MIPS_wrdsp

MIPS_shilov = _ida_allins.MIPS_shilov

MIPS_extr_r_w = _ida_allins.MIPS_extr_r_w

MIPS_extrv_r_w = _ida_allins.MIPS_extrv_r_w

MIPS_extr_rs_w = _ida_allins.MIPS_extr_rs_w

MIPS_extr_s_h = _ida_allins.MIPS_extr_s_h

MIPS_extrv_rs_w = _ida_allins.MIPS_extrv_rs_w

MIPS_extrv_s_h = _ida_allins.MIPS_extrv_s_h

MIPS_mthlip = _ida_allins.MIPS_mthlip

MIPS_dextr_w = _ida_allins.MIPS_dextr_w

MIPS_dextr_l = _ida_allins.MIPS_dextr_l

MIPS_dextrv_w = _ida_allins.MIPS_dextrv_w

MIPS_dextrv_l = _ida_allins.MIPS_dextrv_l

MIPS_dextp = _ida_allins.MIPS_dextp

MIPS_dextpdp = _ida_allins.MIPS_dextpdp

MIPS_dshilo = _ida_allins.MIPS_dshilo

MIPS_dextpv = _ida_allins.MIPS_dextpv

MIPS_dextpdpv = _ida_allins.MIPS_dextpdpv

MIPS_dshilov = _ida_allins.MIPS_dshilov

MIPS_dextr_r_w = _ida_allins.MIPS_dextr_r_w

MIPS_dextr_r_l = _ida_allins.MIPS_dextr_r_l

MIPS_dextrv_r_w = _ida_allins.MIPS_dextrv_r_w

MIPS_dextrv_r_l = _ida_allins.MIPS_dextrv_r_l

MIPS_dextr_rs_w = _ida_allins.MIPS_dextr_rs_w

MIPS_dextr_s_h = _ida_allins.MIPS_dextr_s_h

MIPS_dextr_rs_l = _ida_allins.MIPS_dextr_rs_l

MIPS_dextrv_rs_w = _ida_allins.MIPS_dextrv_rs_w

MIPS_dextrv_s_h = _ida_allins.MIPS_dextrv_s_h

MIPS_dextrv_rs_l = _ida_allins.MIPS_dextrv_rs_l

MIPS_dmthlip = _ida_allins.MIPS_dmthlip

MIPS_adduh_qb = _ida_allins.MIPS_adduh_qb

MIPS_addqh_ph = _ida_allins.MIPS_addqh_ph

MIPS_addqh_w = _ida_allins.MIPS_addqh_w

MIPS_subuh_qb = _ida_allins.MIPS_subuh_qb

MIPS_subqh_ph = _ida_allins.MIPS_subqh_ph

MIPS_subqh_w = _ida_allins.MIPS_subqh_w

MIPS_adduh_r_qb = _ida_allins.MIPS_adduh_r_qb

MIPS_addqh_r_ph = _ida_allins.MIPS_addqh_r_ph

MIPS_addqh_r_w = _ida_allins.MIPS_addqh_r_w

MIPS_subuh_r_qb = _ida_allins.MIPS_subuh_r_qb

MIPS_subqh_r_ph = _ida_allins.MIPS_subqh_r_ph

MIPS_subqh_r_w = _ida_allins.MIPS_subqh_r_w

MIPS_mul_ph = _ida_allins.MIPS_mul_ph

MIPS_mul_s_ph = _ida_allins.MIPS_mul_s_ph

MIPS_mulq_s_w = _ida_allins.MIPS_mulq_s_w

MIPS_mulq_rs_w = _ida_allins.MIPS_mulq_rs_w

MIPS_append = _ida_allins.MIPS_append

MIPS_balign = _ida_allins.MIPS_balign

MIPS_prepend = _ida_allins.MIPS_prepend

MIPS_laa = _ida_allins.MIPS_laa

MIPS_laad = _ida_allins.MIPS_laad

MIPS_lac = _ida_allins.MIPS_lac

MIPS_lacd = _ida_allins.MIPS_lacd

MIPS_lad = _ida_allins.MIPS_lad

MIPS_ladd = _ida_allins.MIPS_ladd

MIPS_lai = _ida_allins.MIPS_lai

MIPS_laid = _ida_allins.MIPS_laid

MIPS_las = _ida_allins.MIPS_las

MIPS_lasd = _ida_allins.MIPS_lasd

MIPS_law = _ida_allins.MIPS_law

MIPS_lawd = _ida_allins.MIPS_lawd

MIPS_lbx = _ida_allins.MIPS_lbx

MIPS_lhux = _ida_allins.MIPS_lhux

MIPS_lwux = _ida_allins.MIPS_lwux

MIPS_qmac_00 = _ida_allins.MIPS_qmac_00

MIPS_qmac_01 = _ida_allins.MIPS_qmac_01

MIPS_qmac_02 = _ida_allins.MIPS_qmac_02

MIPS_qmac_03 = _ida_allins.MIPS_qmac_03

MIPS_qmacs_00 = _ida_allins.MIPS_qmacs_00

MIPS_qmacs_01 = _ida_allins.MIPS_qmacs_01

MIPS_qmacs_02 = _ida_allins.MIPS_qmacs_02

MIPS_qmacs_03 = _ida_allins.MIPS_qmacs_03

MIPS_zcb = _ida_allins.MIPS_zcb

MIPS_zcbt = _ida_allins.MIPS_zcbt

MIPS_msa_sll_b = _ida_allins.MIPS_msa_sll_b

MIPS_msa_sll_h = _ida_allins.MIPS_msa_sll_h

MIPS_msa_sll_w = _ida_allins.MIPS_msa_sll_w

MIPS_msa_sll_d = _ida_allins.MIPS_msa_sll_d

MIPS_msa_slli_b = _ida_allins.MIPS_msa_slli_b

MIPS_msa_slli_h = _ida_allins.MIPS_msa_slli_h

MIPS_msa_slli_w = _ida_allins.MIPS_msa_slli_w

MIPS_msa_slli_d = _ida_allins.MIPS_msa_slli_d

MIPS_msa_sra_b = _ida_allins.MIPS_msa_sra_b

MIPS_msa_sra_h = _ida_allins.MIPS_msa_sra_h

MIPS_msa_sra_w = _ida_allins.MIPS_msa_sra_w

MIPS_msa_sra_d = _ida_allins.MIPS_msa_sra_d

MIPS_msa_srai_b = _ida_allins.MIPS_msa_srai_b

MIPS_msa_srai_h = _ida_allins.MIPS_msa_srai_h

MIPS_msa_srai_w = _ida_allins.MIPS_msa_srai_w

MIPS_msa_srai_d = _ida_allins.MIPS_msa_srai_d

MIPS_msa_srl_b = _ida_allins.MIPS_msa_srl_b

MIPS_msa_srl_h = _ida_allins.MIPS_msa_srl_h

MIPS_msa_srl_w = _ida_allins.MIPS_msa_srl_w

MIPS_msa_srl_d = _ida_allins.MIPS_msa_srl_d

MIPS_msa_srli_b = _ida_allins.MIPS_msa_srli_b

MIPS_msa_srli_h = _ida_allins.MIPS_msa_srli_h

MIPS_msa_srli_w = _ida_allins.MIPS_msa_srli_w

MIPS_msa_srli_d = _ida_allins.MIPS_msa_srli_d

MIPS_msa_bclr_b = _ida_allins.MIPS_msa_bclr_b

MIPS_msa_bclr_h = _ida_allins.MIPS_msa_bclr_h

MIPS_msa_bclr_w = _ida_allins.MIPS_msa_bclr_w

MIPS_msa_bclr_d = _ida_allins.MIPS_msa_bclr_d

MIPS_msa_bclri_b = _ida_allins.MIPS_msa_bclri_b

MIPS_msa_bclri_h = _ida_allins.MIPS_msa_bclri_h

MIPS_msa_bclri_w = _ida_allins.MIPS_msa_bclri_w

MIPS_msa_bclri_d = _ida_allins.MIPS_msa_bclri_d

MIPS_msa_bset_b = _ida_allins.MIPS_msa_bset_b

MIPS_msa_bset_h = _ida_allins.MIPS_msa_bset_h

MIPS_msa_bset_w = _ida_allins.MIPS_msa_bset_w

MIPS_msa_bset_d = _ida_allins.MIPS_msa_bset_d

MIPS_msa_bseti_b = _ida_allins.MIPS_msa_bseti_b

MIPS_msa_bseti_h = _ida_allins.MIPS_msa_bseti_h

MIPS_msa_bseti_w = _ida_allins.MIPS_msa_bseti_w

MIPS_msa_bseti_d = _ida_allins.MIPS_msa_bseti_d

MIPS_msa_bneg_b = _ida_allins.MIPS_msa_bneg_b

MIPS_msa_bneg_h = _ida_allins.MIPS_msa_bneg_h

MIPS_msa_bneg_w = _ida_allins.MIPS_msa_bneg_w

MIPS_msa_bneg_d = _ida_allins.MIPS_msa_bneg_d

MIPS_msa_bnegi_b = _ida_allins.MIPS_msa_bnegi_b

MIPS_msa_bnegi_h = _ida_allins.MIPS_msa_bnegi_h

MIPS_msa_bnegi_w = _ida_allins.MIPS_msa_bnegi_w

MIPS_msa_bnegi_d = _ida_allins.MIPS_msa_bnegi_d

MIPS_msa_binsl_b = _ida_allins.MIPS_msa_binsl_b

MIPS_msa_binsl_h = _ida_allins.MIPS_msa_binsl_h

MIPS_msa_binsl_w = _ida_allins.MIPS_msa_binsl_w

MIPS_msa_binsl_d = _ida_allins.MIPS_msa_binsl_d

MIPS_msa_binsli_b = _ida_allins.MIPS_msa_binsli_b

MIPS_msa_binsli_h = _ida_allins.MIPS_msa_binsli_h

MIPS_msa_binsli_w = _ida_allins.MIPS_msa_binsli_w

MIPS_msa_binsli_d = _ida_allins.MIPS_msa_binsli_d

MIPS_msa_binsr_b = _ida_allins.MIPS_msa_binsr_b

MIPS_msa_binsr_h = _ida_allins.MIPS_msa_binsr_h

MIPS_msa_binsr_w = _ida_allins.MIPS_msa_binsr_w

MIPS_msa_binsr_d = _ida_allins.MIPS_msa_binsr_d

MIPS_msa_binsri_b = _ida_allins.MIPS_msa_binsri_b

MIPS_msa_binsri_h = _ida_allins.MIPS_msa_binsri_h

MIPS_msa_binsri_w = _ida_allins.MIPS_msa_binsri_w

MIPS_msa_binsri_d = _ida_allins.MIPS_msa_binsri_d

MIPS_msa_addv_b = _ida_allins.MIPS_msa_addv_b

MIPS_msa_addv_h = _ida_allins.MIPS_msa_addv_h

MIPS_msa_addv_w = _ida_allins.MIPS_msa_addv_w

MIPS_msa_addv_d = _ida_allins.MIPS_msa_addv_d

MIPS_msa_addvi_b = _ida_allins.MIPS_msa_addvi_b

MIPS_msa_addvi_h = _ida_allins.MIPS_msa_addvi_h

MIPS_msa_addvi_w = _ida_allins.MIPS_msa_addvi_w

MIPS_msa_addvi_d = _ida_allins.MIPS_msa_addvi_d

MIPS_msa_subv_b = _ida_allins.MIPS_msa_subv_b

MIPS_msa_subv_h = _ida_allins.MIPS_msa_subv_h

MIPS_msa_subv_w = _ida_allins.MIPS_msa_subv_w

MIPS_msa_subv_d = _ida_allins.MIPS_msa_subv_d

MIPS_msa_subvi_b = _ida_allins.MIPS_msa_subvi_b

MIPS_msa_subvi_h = _ida_allins.MIPS_msa_subvi_h

MIPS_msa_subvi_w = _ida_allins.MIPS_msa_subvi_w

MIPS_msa_subvi_d = _ida_allins.MIPS_msa_subvi_d

MIPS_msa_max_s_b = _ida_allins.MIPS_msa_max_s_b

MIPS_msa_max_s_h = _ida_allins.MIPS_msa_max_s_h

MIPS_msa_max_s_w = _ida_allins.MIPS_msa_max_s_w

MIPS_msa_max_s_d = _ida_allins.MIPS_msa_max_s_d

MIPS_msa_maxi_s_b = _ida_allins.MIPS_msa_maxi_s_b

MIPS_msa_maxi_s_h = _ida_allins.MIPS_msa_maxi_s_h

MIPS_msa_maxi_s_w = _ida_allins.MIPS_msa_maxi_s_w

MIPS_msa_maxi_s_d = _ida_allins.MIPS_msa_maxi_s_d

MIPS_msa_max_u_b = _ida_allins.MIPS_msa_max_u_b

MIPS_msa_max_u_h = _ida_allins.MIPS_msa_max_u_h

MIPS_msa_max_u_w = _ida_allins.MIPS_msa_max_u_w

MIPS_msa_max_u_d = _ida_allins.MIPS_msa_max_u_d

MIPS_msa_maxi_u_b = _ida_allins.MIPS_msa_maxi_u_b

MIPS_msa_maxi_u_h = _ida_allins.MIPS_msa_maxi_u_h

MIPS_msa_maxi_u_w = _ida_allins.MIPS_msa_maxi_u_w

MIPS_msa_maxi_u_d = _ida_allins.MIPS_msa_maxi_u_d

MIPS_msa_min_s_b = _ida_allins.MIPS_msa_min_s_b

MIPS_msa_min_s_h = _ida_allins.MIPS_msa_min_s_h

MIPS_msa_min_s_w = _ida_allins.MIPS_msa_min_s_w

MIPS_msa_min_s_d = _ida_allins.MIPS_msa_min_s_d

MIPS_msa_mini_s_b = _ida_allins.MIPS_msa_mini_s_b

MIPS_msa_mini_s_h = _ida_allins.MIPS_msa_mini_s_h

MIPS_msa_mini_s_w = _ida_allins.MIPS_msa_mini_s_w

MIPS_msa_mini_s_d = _ida_allins.MIPS_msa_mini_s_d

MIPS_msa_min_u_b = _ida_allins.MIPS_msa_min_u_b

MIPS_msa_min_u_h = _ida_allins.MIPS_msa_min_u_h

MIPS_msa_min_u_w = _ida_allins.MIPS_msa_min_u_w

MIPS_msa_min_u_d = _ida_allins.MIPS_msa_min_u_d

MIPS_msa_mini_u_b = _ida_allins.MIPS_msa_mini_u_b

MIPS_msa_mini_u_h = _ida_allins.MIPS_msa_mini_u_h

MIPS_msa_mini_u_w = _ida_allins.MIPS_msa_mini_u_w

MIPS_msa_mini_u_d = _ida_allins.MIPS_msa_mini_u_d

MIPS_msa_max_a_b = _ida_allins.MIPS_msa_max_a_b

MIPS_msa_max_a_h = _ida_allins.MIPS_msa_max_a_h

MIPS_msa_max_a_w = _ida_allins.MIPS_msa_max_a_w

MIPS_msa_max_a_d = _ida_allins.MIPS_msa_max_a_d

MIPS_msa_min_a_b = _ida_allins.MIPS_msa_min_a_b

MIPS_msa_min_a_h = _ida_allins.MIPS_msa_min_a_h

MIPS_msa_min_a_w = _ida_allins.MIPS_msa_min_a_w

MIPS_msa_min_a_d = _ida_allins.MIPS_msa_min_a_d

MIPS_msa_ceq_b = _ida_allins.MIPS_msa_ceq_b

MIPS_msa_ceq_h = _ida_allins.MIPS_msa_ceq_h

MIPS_msa_ceq_w = _ida_allins.MIPS_msa_ceq_w

MIPS_msa_ceq_d = _ida_allins.MIPS_msa_ceq_d

MIPS_msa_ceqi_b = _ida_allins.MIPS_msa_ceqi_b

MIPS_msa_ceqi_h = _ida_allins.MIPS_msa_ceqi_h

MIPS_msa_ceqi_w = _ida_allins.MIPS_msa_ceqi_w

MIPS_msa_ceqi_d = _ida_allins.MIPS_msa_ceqi_d

MIPS_msa_clt_s_b = _ida_allins.MIPS_msa_clt_s_b

MIPS_msa_clt_s_h = _ida_allins.MIPS_msa_clt_s_h

MIPS_msa_clt_s_w = _ida_allins.MIPS_msa_clt_s_w

MIPS_msa_clt_s_d = _ida_allins.MIPS_msa_clt_s_d

MIPS_msa_clti_s_b = _ida_allins.MIPS_msa_clti_s_b

MIPS_msa_clti_s_h = _ida_allins.MIPS_msa_clti_s_h

MIPS_msa_clti_s_w = _ida_allins.MIPS_msa_clti_s_w

MIPS_msa_clti_s_d = _ida_allins.MIPS_msa_clti_s_d

MIPS_msa_clt_u_b = _ida_allins.MIPS_msa_clt_u_b

MIPS_msa_clt_u_h = _ida_allins.MIPS_msa_clt_u_h

MIPS_msa_clt_u_w = _ida_allins.MIPS_msa_clt_u_w

MIPS_msa_clt_u_d = _ida_allins.MIPS_msa_clt_u_d

MIPS_msa_clti_u_b = _ida_allins.MIPS_msa_clti_u_b

MIPS_msa_clti_u_h = _ida_allins.MIPS_msa_clti_u_h

MIPS_msa_clti_u_w = _ida_allins.MIPS_msa_clti_u_w

MIPS_msa_clti_u_d = _ida_allins.MIPS_msa_clti_u_d

MIPS_msa_cle_s_b = _ida_allins.MIPS_msa_cle_s_b

MIPS_msa_cle_s_h = _ida_allins.MIPS_msa_cle_s_h

MIPS_msa_cle_s_w = _ida_allins.MIPS_msa_cle_s_w

MIPS_msa_cle_s_d = _ida_allins.MIPS_msa_cle_s_d

MIPS_msa_clei_s_b = _ida_allins.MIPS_msa_clei_s_b

MIPS_msa_clei_s_h = _ida_allins.MIPS_msa_clei_s_h

MIPS_msa_clei_s_w = _ida_allins.MIPS_msa_clei_s_w

MIPS_msa_clei_s_d = _ida_allins.MIPS_msa_clei_s_d

MIPS_msa_cle_u_b = _ida_allins.MIPS_msa_cle_u_b

MIPS_msa_cle_u_h = _ida_allins.MIPS_msa_cle_u_h

MIPS_msa_cle_u_w = _ida_allins.MIPS_msa_cle_u_w

MIPS_msa_cle_u_d = _ida_allins.MIPS_msa_cle_u_d

MIPS_msa_clei_u_b = _ida_allins.MIPS_msa_clei_u_b

MIPS_msa_clei_u_h = _ida_allins.MIPS_msa_clei_u_h

MIPS_msa_clei_u_w = _ida_allins.MIPS_msa_clei_u_w

MIPS_msa_clei_u_d = _ida_allins.MIPS_msa_clei_u_d

MIPS_msa_ld_b = _ida_allins.MIPS_msa_ld_b

MIPS_msa_ld_h = _ida_allins.MIPS_msa_ld_h

MIPS_msa_ld_w = _ida_allins.MIPS_msa_ld_w

MIPS_msa_ld_d = _ida_allins.MIPS_msa_ld_d

MIPS_msa_st_b = _ida_allins.MIPS_msa_st_b

MIPS_msa_st_h = _ida_allins.MIPS_msa_st_h

MIPS_msa_st_w = _ida_allins.MIPS_msa_st_w

MIPS_msa_st_d = _ida_allins.MIPS_msa_st_d

MIPS_msa_sat_s_b = _ida_allins.MIPS_msa_sat_s_b

MIPS_msa_sat_s_h = _ida_allins.MIPS_msa_sat_s_h

MIPS_msa_sat_s_w = _ida_allins.MIPS_msa_sat_s_w

MIPS_msa_sat_s_d = _ida_allins.MIPS_msa_sat_s_d

MIPS_msa_sat_u_b = _ida_allins.MIPS_msa_sat_u_b

MIPS_msa_sat_u_h = _ida_allins.MIPS_msa_sat_u_h

MIPS_msa_sat_u_w = _ida_allins.MIPS_msa_sat_u_w

MIPS_msa_sat_u_d = _ida_allins.MIPS_msa_sat_u_d

MIPS_msa_add_a_b = _ida_allins.MIPS_msa_add_a_b

MIPS_msa_add_a_h = _ida_allins.MIPS_msa_add_a_h

MIPS_msa_add_a_w = _ida_allins.MIPS_msa_add_a_w

MIPS_msa_add_a_d = _ida_allins.MIPS_msa_add_a_d

MIPS_msa_adds_a_b = _ida_allins.MIPS_msa_adds_a_b

MIPS_msa_adds_a_h = _ida_allins.MIPS_msa_adds_a_h

MIPS_msa_adds_a_w = _ida_allins.MIPS_msa_adds_a_w

MIPS_msa_adds_a_d = _ida_allins.MIPS_msa_adds_a_d

MIPS_msa_adds_s_b = _ida_allins.MIPS_msa_adds_s_b

MIPS_msa_adds_s_h = _ida_allins.MIPS_msa_adds_s_h

MIPS_msa_adds_s_w = _ida_allins.MIPS_msa_adds_s_w

MIPS_msa_adds_s_d = _ida_allins.MIPS_msa_adds_s_d

MIPS_msa_adds_u_b = _ida_allins.MIPS_msa_adds_u_b

MIPS_msa_adds_u_h = _ida_allins.MIPS_msa_adds_u_h

MIPS_msa_adds_u_w = _ida_allins.MIPS_msa_adds_u_w

MIPS_msa_adds_u_d = _ida_allins.MIPS_msa_adds_u_d

MIPS_msa_ave_s_b = _ida_allins.MIPS_msa_ave_s_b

MIPS_msa_ave_s_h = _ida_allins.MIPS_msa_ave_s_h

MIPS_msa_ave_s_w = _ida_allins.MIPS_msa_ave_s_w

MIPS_msa_ave_s_d = _ida_allins.MIPS_msa_ave_s_d

MIPS_msa_ave_u_b = _ida_allins.MIPS_msa_ave_u_b

MIPS_msa_ave_u_h = _ida_allins.MIPS_msa_ave_u_h

MIPS_msa_ave_u_w = _ida_allins.MIPS_msa_ave_u_w

MIPS_msa_ave_u_d = _ida_allins.MIPS_msa_ave_u_d

MIPS_msa_aver_s_b = _ida_allins.MIPS_msa_aver_s_b

MIPS_msa_aver_s_h = _ida_allins.MIPS_msa_aver_s_h

MIPS_msa_aver_s_w = _ida_allins.MIPS_msa_aver_s_w

MIPS_msa_aver_s_d = _ida_allins.MIPS_msa_aver_s_d

MIPS_msa_aver_u_b = _ida_allins.MIPS_msa_aver_u_b

MIPS_msa_aver_u_h = _ida_allins.MIPS_msa_aver_u_h

MIPS_msa_aver_u_w = _ida_allins.MIPS_msa_aver_u_w

MIPS_msa_aver_u_d = _ida_allins.MIPS_msa_aver_u_d

MIPS_msa_subs_s_b = _ida_allins.MIPS_msa_subs_s_b

MIPS_msa_subs_s_h = _ida_allins.MIPS_msa_subs_s_h

MIPS_msa_subs_s_w = _ida_allins.MIPS_msa_subs_s_w

MIPS_msa_subs_s_d = _ida_allins.MIPS_msa_subs_s_d

MIPS_msa_subs_u_b = _ida_allins.MIPS_msa_subs_u_b

MIPS_msa_subs_u_h = _ida_allins.MIPS_msa_subs_u_h

MIPS_msa_subs_u_w = _ida_allins.MIPS_msa_subs_u_w

MIPS_msa_subs_u_d = _ida_allins.MIPS_msa_subs_u_d

MIPS_msa_subsus_u_b = _ida_allins.MIPS_msa_subsus_u_b

MIPS_msa_subsus_u_h = _ida_allins.MIPS_msa_subsus_u_h

MIPS_msa_subsus_u_w = _ida_allins.MIPS_msa_subsus_u_w

MIPS_msa_subsus_u_d = _ida_allins.MIPS_msa_subsus_u_d

MIPS_msa_subsuu_s_b = _ida_allins.MIPS_msa_subsuu_s_b

MIPS_msa_subsuu_s_h = _ida_allins.MIPS_msa_subsuu_s_h

MIPS_msa_subsuu_s_w = _ida_allins.MIPS_msa_subsuu_s_w

MIPS_msa_subsuu_s_d = _ida_allins.MIPS_msa_subsuu_s_d

MIPS_msa_asub_s_b = _ida_allins.MIPS_msa_asub_s_b

MIPS_msa_asub_s_h = _ida_allins.MIPS_msa_asub_s_h

MIPS_msa_asub_s_w = _ida_allins.MIPS_msa_asub_s_w

MIPS_msa_asub_s_d = _ida_allins.MIPS_msa_asub_s_d

MIPS_msa_asub_u_b = _ida_allins.MIPS_msa_asub_u_b

MIPS_msa_asub_u_h = _ida_allins.MIPS_msa_asub_u_h

MIPS_msa_asub_u_w = _ida_allins.MIPS_msa_asub_u_w

MIPS_msa_asub_u_d = _ida_allins.MIPS_msa_asub_u_d

MIPS_msa_mulv_b = _ida_allins.MIPS_msa_mulv_b

MIPS_msa_mulv_h = _ida_allins.MIPS_msa_mulv_h

MIPS_msa_mulv_w = _ida_allins.MIPS_msa_mulv_w

MIPS_msa_mulv_d = _ida_allins.MIPS_msa_mulv_d

MIPS_msa_maddv_b = _ida_allins.MIPS_msa_maddv_b

MIPS_msa_maddv_h = _ida_allins.MIPS_msa_maddv_h

MIPS_msa_maddv_w = _ida_allins.MIPS_msa_maddv_w

MIPS_msa_maddv_d = _ida_allins.MIPS_msa_maddv_d

MIPS_msa_msubv_b = _ida_allins.MIPS_msa_msubv_b

MIPS_msa_msubv_h = _ida_allins.MIPS_msa_msubv_h

MIPS_msa_msubv_w = _ida_allins.MIPS_msa_msubv_w

MIPS_msa_msubv_d = _ida_allins.MIPS_msa_msubv_d

MIPS_msa_div_s_b = _ida_allins.MIPS_msa_div_s_b

MIPS_msa_div_s_h = _ida_allins.MIPS_msa_div_s_h

MIPS_msa_div_s_w = _ida_allins.MIPS_msa_div_s_w

MIPS_msa_div_s_d = _ida_allins.MIPS_msa_div_s_d

MIPS_msa_div_u_b = _ida_allins.MIPS_msa_div_u_b

MIPS_msa_div_u_h = _ida_allins.MIPS_msa_div_u_h

MIPS_msa_div_u_w = _ida_allins.MIPS_msa_div_u_w

MIPS_msa_div_u_d = _ida_allins.MIPS_msa_div_u_d

MIPS_msa_mod_s_b = _ida_allins.MIPS_msa_mod_s_b

MIPS_msa_mod_s_h = _ida_allins.MIPS_msa_mod_s_h

MIPS_msa_mod_s_w = _ida_allins.MIPS_msa_mod_s_w

MIPS_msa_mod_s_d = _ida_allins.MIPS_msa_mod_s_d

MIPS_msa_mod_u_b = _ida_allins.MIPS_msa_mod_u_b

MIPS_msa_mod_u_h = _ida_allins.MIPS_msa_mod_u_h

MIPS_msa_mod_u_w = _ida_allins.MIPS_msa_mod_u_w

MIPS_msa_mod_u_d = _ida_allins.MIPS_msa_mod_u_d

MIPS_msa_dotp_s_h = _ida_allins.MIPS_msa_dotp_s_h

MIPS_msa_dotp_s_w = _ida_allins.MIPS_msa_dotp_s_w

MIPS_msa_dotp_s_d = _ida_allins.MIPS_msa_dotp_s_d

MIPS_msa_dotp_u_h = _ida_allins.MIPS_msa_dotp_u_h

MIPS_msa_dotp_u_w = _ida_allins.MIPS_msa_dotp_u_w

MIPS_msa_dotp_u_d = _ida_allins.MIPS_msa_dotp_u_d

MIPS_msa_dpadd_s_h = _ida_allins.MIPS_msa_dpadd_s_h

MIPS_msa_dpadd_s_w = _ida_allins.MIPS_msa_dpadd_s_w

MIPS_msa_dpadd_s_d = _ida_allins.MIPS_msa_dpadd_s_d

MIPS_msa_dpadd_u_h = _ida_allins.MIPS_msa_dpadd_u_h

MIPS_msa_dpadd_u_w = _ida_allins.MIPS_msa_dpadd_u_w

MIPS_msa_dpadd_u_d = _ida_allins.MIPS_msa_dpadd_u_d

MIPS_msa_dpsub_s_h = _ida_allins.MIPS_msa_dpsub_s_h

MIPS_msa_dpsub_s_w = _ida_allins.MIPS_msa_dpsub_s_w

MIPS_msa_dpsub_s_d = _ida_allins.MIPS_msa_dpsub_s_d

MIPS_msa_dpsub_u_h = _ida_allins.MIPS_msa_dpsub_u_h

MIPS_msa_dpsub_u_w = _ida_allins.MIPS_msa_dpsub_u_w

MIPS_msa_dpsub_u_d = _ida_allins.MIPS_msa_dpsub_u_d

MIPS_msa_sld_b = _ida_allins.MIPS_msa_sld_b

MIPS_msa_sld_h = _ida_allins.MIPS_msa_sld_h

MIPS_msa_sld_w = _ida_allins.MIPS_msa_sld_w

MIPS_msa_sld_d = _ida_allins.MIPS_msa_sld_d

MIPS_msa_sldi_b = _ida_allins.MIPS_msa_sldi_b

MIPS_msa_sldi_h = _ida_allins.MIPS_msa_sldi_h

MIPS_msa_sldi_w = _ida_allins.MIPS_msa_sldi_w

MIPS_msa_sldi_d = _ida_allins.MIPS_msa_sldi_d

MIPS_msa_splat_b = _ida_allins.MIPS_msa_splat_b

MIPS_msa_splat_h = _ida_allins.MIPS_msa_splat_h

MIPS_msa_splat_w = _ida_allins.MIPS_msa_splat_w

MIPS_msa_splat_d = _ida_allins.MIPS_msa_splat_d

MIPS_msa_splati_b = _ida_allins.MIPS_msa_splati_b

MIPS_msa_splati_h = _ida_allins.MIPS_msa_splati_h

MIPS_msa_splati_w = _ida_allins.MIPS_msa_splati_w

MIPS_msa_splati_d = _ida_allins.MIPS_msa_splati_d

MIPS_msa_pckev_b = _ida_allins.MIPS_msa_pckev_b

MIPS_msa_pckev_h = _ida_allins.MIPS_msa_pckev_h

MIPS_msa_pckev_w = _ida_allins.MIPS_msa_pckev_w

MIPS_msa_pckev_d = _ida_allins.MIPS_msa_pckev_d

MIPS_msa_pckod_b = _ida_allins.MIPS_msa_pckod_b

MIPS_msa_pckod_h = _ida_allins.MIPS_msa_pckod_h

MIPS_msa_pckod_w = _ida_allins.MIPS_msa_pckod_w

MIPS_msa_pckod_d = _ida_allins.MIPS_msa_pckod_d

MIPS_msa_ilvl_b = _ida_allins.MIPS_msa_ilvl_b

MIPS_msa_ilvl_h = _ida_allins.MIPS_msa_ilvl_h

MIPS_msa_ilvl_w = _ida_allins.MIPS_msa_ilvl_w

MIPS_msa_ilvl_d = _ida_allins.MIPS_msa_ilvl_d

MIPS_msa_ilvr_b = _ida_allins.MIPS_msa_ilvr_b

MIPS_msa_ilvr_h = _ida_allins.MIPS_msa_ilvr_h

MIPS_msa_ilvr_w = _ida_allins.MIPS_msa_ilvr_w

MIPS_msa_ilvr_d = _ida_allins.MIPS_msa_ilvr_d

MIPS_msa_ilvev_b = _ida_allins.MIPS_msa_ilvev_b

MIPS_msa_ilvev_h = _ida_allins.MIPS_msa_ilvev_h

MIPS_msa_ilvev_w = _ida_allins.MIPS_msa_ilvev_w

MIPS_msa_ilvev_d = _ida_allins.MIPS_msa_ilvev_d

MIPS_msa_ilvod_b = _ida_allins.MIPS_msa_ilvod_b

MIPS_msa_ilvod_h = _ida_allins.MIPS_msa_ilvod_h

MIPS_msa_ilvod_w = _ida_allins.MIPS_msa_ilvod_w

MIPS_msa_ilvod_d = _ida_allins.MIPS_msa_ilvod_d

MIPS_msa_vshf_b = _ida_allins.MIPS_msa_vshf_b

MIPS_msa_vshf_h = _ida_allins.MIPS_msa_vshf_h

MIPS_msa_vshf_w = _ida_allins.MIPS_msa_vshf_w

MIPS_msa_vshf_d = _ida_allins.MIPS_msa_vshf_d

MIPS_msa_srar_b = _ida_allins.MIPS_msa_srar_b

MIPS_msa_srar_h = _ida_allins.MIPS_msa_srar_h

MIPS_msa_srar_w = _ida_allins.MIPS_msa_srar_w

MIPS_msa_srar_d = _ida_allins.MIPS_msa_srar_d

MIPS_msa_srari_b = _ida_allins.MIPS_msa_srari_b

MIPS_msa_srari_h = _ida_allins.MIPS_msa_srari_h

MIPS_msa_srari_w = _ida_allins.MIPS_msa_srari_w

MIPS_msa_srari_d = _ida_allins.MIPS_msa_srari_d

MIPS_msa_srlr_b = _ida_allins.MIPS_msa_srlr_b

MIPS_msa_srlr_h = _ida_allins.MIPS_msa_srlr_h

MIPS_msa_srlr_w = _ida_allins.MIPS_msa_srlr_w

MIPS_msa_srlr_d = _ida_allins.MIPS_msa_srlr_d

MIPS_msa_srlri_b = _ida_allins.MIPS_msa_srlri_b

MIPS_msa_srlri_h = _ida_allins.MIPS_msa_srlri_h

MIPS_msa_srlri_w = _ida_allins.MIPS_msa_srlri_w

MIPS_msa_srlri_d = _ida_allins.MIPS_msa_srlri_d

MIPS_msa_hadd_s_h = _ida_allins.MIPS_msa_hadd_s_h

MIPS_msa_hadd_s_w = _ida_allins.MIPS_msa_hadd_s_w

MIPS_msa_hadd_s_d = _ida_allins.MIPS_msa_hadd_s_d

MIPS_msa_hadd_u_h = _ida_allins.MIPS_msa_hadd_u_h

MIPS_msa_hadd_u_w = _ida_allins.MIPS_msa_hadd_u_w

MIPS_msa_hadd_u_d = _ida_allins.MIPS_msa_hadd_u_d

MIPS_msa_hsub_s_h = _ida_allins.MIPS_msa_hsub_s_h

MIPS_msa_hsub_s_w = _ida_allins.MIPS_msa_hsub_s_w

MIPS_msa_hsub_s_d = _ida_allins.MIPS_msa_hsub_s_d

MIPS_msa_hsub_u_h = _ida_allins.MIPS_msa_hsub_u_h

MIPS_msa_hsub_u_w = _ida_allins.MIPS_msa_hsub_u_w

MIPS_msa_hsub_u_d = _ida_allins.MIPS_msa_hsub_u_d

MIPS_msa_and_v = _ida_allins.MIPS_msa_and_v

MIPS_msa_andi_b = _ida_allins.MIPS_msa_andi_b

MIPS_msa_or_v = _ida_allins.MIPS_msa_or_v

MIPS_msa_ori_b = _ida_allins.MIPS_msa_ori_b

MIPS_msa_nor_v = _ida_allins.MIPS_msa_nor_v

MIPS_msa_nori_b = _ida_allins.MIPS_msa_nori_b

MIPS_msa_xor_v = _ida_allins.MIPS_msa_xor_v

MIPS_msa_xori_b = _ida_allins.MIPS_msa_xori_b

MIPS_msa_bmnz_v = _ida_allins.MIPS_msa_bmnz_v

MIPS_msa_bmnzi_b = _ida_allins.MIPS_msa_bmnzi_b

MIPS_msa_bmz_v = _ida_allins.MIPS_msa_bmz_v

MIPS_msa_bmzi_b = _ida_allins.MIPS_msa_bmzi_b

MIPS_msa_bsel_v = _ida_allins.MIPS_msa_bsel_v

MIPS_msa_bseli_b = _ida_allins.MIPS_msa_bseli_b

MIPS_msa_shf_b = _ida_allins.MIPS_msa_shf_b

MIPS_msa_shf_h = _ida_allins.MIPS_msa_shf_h

MIPS_msa_shf_w = _ida_allins.MIPS_msa_shf_w

MIPS_msa_bnz_v = _ida_allins.MIPS_msa_bnz_v

MIPS_msa_bz_v = _ida_allins.MIPS_msa_bz_v

MIPS_msa_fill_b = _ida_allins.MIPS_msa_fill_b

MIPS_msa_fill_h = _ida_allins.MIPS_msa_fill_h

MIPS_msa_fill_w = _ida_allins.MIPS_msa_fill_w

MIPS_msa_fill_d = _ida_allins.MIPS_msa_fill_d

MIPS_msa_pcnt_b = _ida_allins.MIPS_msa_pcnt_b

MIPS_msa_pcnt_h = _ida_allins.MIPS_msa_pcnt_h

MIPS_msa_pcnt_w = _ida_allins.MIPS_msa_pcnt_w

MIPS_msa_pcnt_d = _ida_allins.MIPS_msa_pcnt_d

MIPS_msa_nloc_b = _ida_allins.MIPS_msa_nloc_b

MIPS_msa_nloc_h = _ida_allins.MIPS_msa_nloc_h

MIPS_msa_nloc_w = _ida_allins.MIPS_msa_nloc_w

MIPS_msa_nloc_d = _ida_allins.MIPS_msa_nloc_d

MIPS_msa_nlzc_b = _ida_allins.MIPS_msa_nlzc_b

MIPS_msa_nlzc_h = _ida_allins.MIPS_msa_nlzc_h

MIPS_msa_nlzc_w = _ida_allins.MIPS_msa_nlzc_w

MIPS_msa_nlzc_d = _ida_allins.MIPS_msa_nlzc_d

MIPS_msa_copy_s_b = _ida_allins.MIPS_msa_copy_s_b

MIPS_msa_copy_s_h = _ida_allins.MIPS_msa_copy_s_h

MIPS_msa_copy_s_w = _ida_allins.MIPS_msa_copy_s_w

MIPS_msa_copy_s_d = _ida_allins.MIPS_msa_copy_s_d

MIPS_msa_copy_u_b = _ida_allins.MIPS_msa_copy_u_b

MIPS_msa_copy_u_h = _ida_allins.MIPS_msa_copy_u_h

MIPS_msa_copy_u_w = _ida_allins.MIPS_msa_copy_u_w

MIPS_msa_copy_u_d = _ida_allins.MIPS_msa_copy_u_d

MIPS_msa_insert_b = _ida_allins.MIPS_msa_insert_b

MIPS_msa_insert_h = _ida_allins.MIPS_msa_insert_h

MIPS_msa_insert_w = _ida_allins.MIPS_msa_insert_w

MIPS_msa_insert_d = _ida_allins.MIPS_msa_insert_d

MIPS_msa_insve_b = _ida_allins.MIPS_msa_insve_b

MIPS_msa_insve_h = _ida_allins.MIPS_msa_insve_h

MIPS_msa_insve_w = _ida_allins.MIPS_msa_insve_w

MIPS_msa_insve_d = _ida_allins.MIPS_msa_insve_d

MIPS_msa_bnz_b = _ida_allins.MIPS_msa_bnz_b

MIPS_msa_bnz_h = _ida_allins.MIPS_msa_bnz_h

MIPS_msa_bnz_w = _ida_allins.MIPS_msa_bnz_w

MIPS_msa_bnz_d = _ida_allins.MIPS_msa_bnz_d

MIPS_msa_bz_b = _ida_allins.MIPS_msa_bz_b

MIPS_msa_bz_h = _ida_allins.MIPS_msa_bz_h

MIPS_msa_bz_w = _ida_allins.MIPS_msa_bz_w

MIPS_msa_bz_d = _ida_allins.MIPS_msa_bz_d

MIPS_msa_ldi_b = _ida_allins.MIPS_msa_ldi_b

MIPS_msa_ldi_h = _ida_allins.MIPS_msa_ldi_h

MIPS_msa_ldi_w = _ida_allins.MIPS_msa_ldi_w

MIPS_msa_ldi_d = _ida_allins.MIPS_msa_ldi_d

MIPS_msa_fcaf_w = _ida_allins.MIPS_msa_fcaf_w

MIPS_msa_fcaf_d = _ida_allins.MIPS_msa_fcaf_d

MIPS_msa_fcun_w = _ida_allins.MIPS_msa_fcun_w

MIPS_msa_fcun_d = _ida_allins.MIPS_msa_fcun_d

MIPS_msa_fceq_w = _ida_allins.MIPS_msa_fceq_w

MIPS_msa_fceq_d = _ida_allins.MIPS_msa_fceq_d

MIPS_msa_fcueq_w = _ida_allins.MIPS_msa_fcueq_w

MIPS_msa_fcueq_d = _ida_allins.MIPS_msa_fcueq_d

MIPS_msa_fclt_w = _ida_allins.MIPS_msa_fclt_w

MIPS_msa_fclt_d = _ida_allins.MIPS_msa_fclt_d

MIPS_msa_fcult_w = _ida_allins.MIPS_msa_fcult_w

MIPS_msa_fcult_d = _ida_allins.MIPS_msa_fcult_d

MIPS_msa_fcle_w = _ida_allins.MIPS_msa_fcle_w

MIPS_msa_fcle_d = _ida_allins.MIPS_msa_fcle_d

MIPS_msa_fcule_w = _ida_allins.MIPS_msa_fcule_w

MIPS_msa_fcule_d = _ida_allins.MIPS_msa_fcule_d

MIPS_msa_fsaf_w = _ida_allins.MIPS_msa_fsaf_w

MIPS_msa_fsaf_d = _ida_allins.MIPS_msa_fsaf_d

MIPS_msa_fsun_w = _ida_allins.MIPS_msa_fsun_w

MIPS_msa_fsun_d = _ida_allins.MIPS_msa_fsun_d

MIPS_msa_fseq_w = _ida_allins.MIPS_msa_fseq_w

MIPS_msa_fseq_d = _ida_allins.MIPS_msa_fseq_d

MIPS_msa_fsueq_w = _ida_allins.MIPS_msa_fsueq_w

MIPS_msa_fsueq_d = _ida_allins.MIPS_msa_fsueq_d

MIPS_msa_fslt_w = _ida_allins.MIPS_msa_fslt_w

MIPS_msa_fslt_d = _ida_allins.MIPS_msa_fslt_d

MIPS_msa_fsult_w = _ida_allins.MIPS_msa_fsult_w

MIPS_msa_fsult_d = _ida_allins.MIPS_msa_fsult_d

MIPS_msa_fsle_w = _ida_allins.MIPS_msa_fsle_w

MIPS_msa_fsle_d = _ida_allins.MIPS_msa_fsle_d

MIPS_msa_fsule_w = _ida_allins.MIPS_msa_fsule_w

MIPS_msa_fsule_d = _ida_allins.MIPS_msa_fsule_d

MIPS_msa_fadd_w = _ida_allins.MIPS_msa_fadd_w

MIPS_msa_fadd_d = _ida_allins.MIPS_msa_fadd_d

MIPS_msa_fsub_w = _ida_allins.MIPS_msa_fsub_w

MIPS_msa_fsub_d = _ida_allins.MIPS_msa_fsub_d

MIPS_msa_fmul_w = _ida_allins.MIPS_msa_fmul_w

MIPS_msa_fmul_d = _ida_allins.MIPS_msa_fmul_d

MIPS_msa_fdiv_w = _ida_allins.MIPS_msa_fdiv_w

MIPS_msa_fdiv_d = _ida_allins.MIPS_msa_fdiv_d

MIPS_msa_fmadd_w = _ida_allins.MIPS_msa_fmadd_w

MIPS_msa_fmadd_d = _ida_allins.MIPS_msa_fmadd_d

MIPS_msa_fmsub_w = _ida_allins.MIPS_msa_fmsub_w

MIPS_msa_fmsub_d = _ida_allins.MIPS_msa_fmsub_d

MIPS_msa_fexp2_w = _ida_allins.MIPS_msa_fexp2_w

MIPS_msa_fexp2_d = _ida_allins.MIPS_msa_fexp2_d

MIPS_msa_fexdo_h = _ida_allins.MIPS_msa_fexdo_h

MIPS_msa_fexdo_w = _ida_allins.MIPS_msa_fexdo_w

MIPS_msa_ftq_h = _ida_allins.MIPS_msa_ftq_h

MIPS_msa_ftq_w = _ida_allins.MIPS_msa_ftq_w

MIPS_msa_fmin_w = _ida_allins.MIPS_msa_fmin_w

MIPS_msa_fmin_d = _ida_allins.MIPS_msa_fmin_d

MIPS_msa_fmin_a_w = _ida_allins.MIPS_msa_fmin_a_w

MIPS_msa_fmin_a_d = _ida_allins.MIPS_msa_fmin_a_d

MIPS_msa_fmax_w = _ida_allins.MIPS_msa_fmax_w

MIPS_msa_fmax_d = _ida_allins.MIPS_msa_fmax_d

MIPS_msa_fmax_a_w = _ida_allins.MIPS_msa_fmax_a_w

MIPS_msa_fmax_a_d = _ida_allins.MIPS_msa_fmax_a_d

MIPS_msa_fcor_w = _ida_allins.MIPS_msa_fcor_w

MIPS_msa_fcor_d = _ida_allins.MIPS_msa_fcor_d

MIPS_msa_fcune_w = _ida_allins.MIPS_msa_fcune_w

MIPS_msa_fcune_d = _ida_allins.MIPS_msa_fcune_d

MIPS_msa_fcne_w = _ida_allins.MIPS_msa_fcne_w

MIPS_msa_fcne_d = _ida_allins.MIPS_msa_fcne_d

MIPS_msa_mul_q_h = _ida_allins.MIPS_msa_mul_q_h

MIPS_msa_mul_q_w = _ida_allins.MIPS_msa_mul_q_w

MIPS_msa_madd_q_h = _ida_allins.MIPS_msa_madd_q_h

MIPS_msa_madd_q_w = _ida_allins.MIPS_msa_madd_q_w

MIPS_msa_msub_q_h = _ida_allins.MIPS_msa_msub_q_h

MIPS_msa_msub_q_w = _ida_allins.MIPS_msa_msub_q_w

MIPS_msa_fsor_w = _ida_allins.MIPS_msa_fsor_w

MIPS_msa_fsor_d = _ida_allins.MIPS_msa_fsor_d

MIPS_msa_fsune_w = _ida_allins.MIPS_msa_fsune_w

MIPS_msa_fsune_d = _ida_allins.MIPS_msa_fsune_d

MIPS_msa_fsne_w = _ida_allins.MIPS_msa_fsne_w

MIPS_msa_fsne_d = _ida_allins.MIPS_msa_fsne_d

MIPS_msa_mulr_q_h = _ida_allins.MIPS_msa_mulr_q_h

MIPS_msa_mulr_q_w = _ida_allins.MIPS_msa_mulr_q_w

MIPS_msa_maddr_q_h = _ida_allins.MIPS_msa_maddr_q_h

MIPS_msa_maddr_q_w = _ida_allins.MIPS_msa_maddr_q_w

MIPS_msa_msubr_q_h = _ida_allins.MIPS_msa_msubr_q_h

MIPS_msa_msubr_q_w = _ida_allins.MIPS_msa_msubr_q_w

MIPS_msa_fclass_w = _ida_allins.MIPS_msa_fclass_w

MIPS_msa_fclass_d = _ida_allins.MIPS_msa_fclass_d

MIPS_msa_ftrunc_s_w = _ida_allins.MIPS_msa_ftrunc_s_w

MIPS_msa_ftrunc_s_d = _ida_allins.MIPS_msa_ftrunc_s_d

MIPS_msa_ftrunc_u_w = _ida_allins.MIPS_msa_ftrunc_u_w

MIPS_msa_ftrunc_u_d = _ida_allins.MIPS_msa_ftrunc_u_d

MIPS_msa_fsqrt_w = _ida_allins.MIPS_msa_fsqrt_w

MIPS_msa_fsqrt_d = _ida_allins.MIPS_msa_fsqrt_d

MIPS_msa_frsqrt_w = _ida_allins.MIPS_msa_frsqrt_w

MIPS_msa_frsqrt_d = _ida_allins.MIPS_msa_frsqrt_d

MIPS_msa_frcp_w = _ida_allins.MIPS_msa_frcp_w

MIPS_msa_frcp_d = _ida_allins.MIPS_msa_frcp_d

MIPS_msa_frint_w = _ida_allins.MIPS_msa_frint_w

MIPS_msa_frint_d = _ida_allins.MIPS_msa_frint_d

MIPS_msa_flog2_w = _ida_allins.MIPS_msa_flog2_w

MIPS_msa_flog2_d = _ida_allins.MIPS_msa_flog2_d

MIPS_msa_fexupl_w = _ida_allins.MIPS_msa_fexupl_w

MIPS_msa_fexupl_d = _ida_allins.MIPS_msa_fexupl_d

MIPS_msa_fexupr_w = _ida_allins.MIPS_msa_fexupr_w

MIPS_msa_fexupr_d = _ida_allins.MIPS_msa_fexupr_d

MIPS_msa_ffql_w = _ida_allins.MIPS_msa_ffql_w

MIPS_msa_ffql_d = _ida_allins.MIPS_msa_ffql_d

MIPS_msa_ffqr_w = _ida_allins.MIPS_msa_ffqr_w

MIPS_msa_ffqr_d = _ida_allins.MIPS_msa_ffqr_d

MIPS_msa_ftint_s_w = _ida_allins.MIPS_msa_ftint_s_w

MIPS_msa_ftint_s_d = _ida_allins.MIPS_msa_ftint_s_d

MIPS_msa_ftint_u_w = _ida_allins.MIPS_msa_ftint_u_w

MIPS_msa_ftint_u_d = _ida_allins.MIPS_msa_ftint_u_d

MIPS_msa_ffint_s_w = _ida_allins.MIPS_msa_ffint_s_w

MIPS_msa_ffint_s_d = _ida_allins.MIPS_msa_ffint_s_d

MIPS_msa_ffint_u_w = _ida_allins.MIPS_msa_ffint_u_w

MIPS_msa_ffint_u_d = _ida_allins.MIPS_msa_ffint_u_d

MIPS_msa_ctcmsa = _ida_allins.MIPS_msa_ctcmsa

MIPS_msa_cfcmsa = _ida_allins.MIPS_msa_cfcmsa

MIPS_msa_move_v = _ida_allins.MIPS_msa_move_v

MIPS_lsa = _ida_allins.MIPS_lsa

MIPS_dlsa = _ida_allins.MIPS_dlsa

MIPS_lbe = _ida_allins.MIPS_lbe

MIPS_lbue = _ida_allins.MIPS_lbue

MIPS_lhe = _ida_allins.MIPS_lhe

MIPS_lhue = _ida_allins.MIPS_lhue

MIPS_lwe = _ida_allins.MIPS_lwe

MIPS_sbe = _ida_allins.MIPS_sbe

MIPS_she = _ida_allins.MIPS_she

MIPS_swe = _ida_allins.MIPS_swe

MIPS_lle = _ida_allins.MIPS_lle

MIPS_sce = _ida_allins.MIPS_sce

MIPS_cachee = _ida_allins.MIPS_cachee

MIPS_prefe = _ida_allins.MIPS_prefe

MIPS_lwle = _ida_allins.MIPS_lwle

MIPS_lwre = _ida_allins.MIPS_lwre

MIPS_swle = _ida_allins.MIPS_swle

MIPS_swre = _ida_allins.MIPS_swre

MIPS_movtz = _ida_allins.MIPS_movtz

MIPS_movtn = _ida_allins.MIPS_movtn

MIPS_copyw = _ida_allins.MIPS_copyw

MIPS_ucopyw = _ida_allins.MIPS_ucopyw

MIPS_last = _ida_allins.MIPS_last

H8_null = _ida_allins.H8_null

H8_add = _ida_allins.H8_add

H8_adds = _ida_allins.H8_adds

H8_addx = _ida_allins.H8_addx

H8_and = _ida_allins.H8_and

H8_andc = _ida_allins.H8_andc

H8_band = _ida_allins.H8_band

H8_bra = _ida_allins.H8_bra

H8_brn = _ida_allins.H8_brn

H8_bhi = _ida_allins.H8_bhi

H8_bls = _ida_allins.H8_bls

H8_bcc = _ida_allins.H8_bcc

H8_bcs = _ida_allins.H8_bcs

H8_bne = _ida_allins.H8_bne

H8_beq = _ida_allins.H8_beq

H8_bvc = _ida_allins.H8_bvc

H8_bvs = _ida_allins.H8_bvs

H8_bpl = _ida_allins.H8_bpl

H8_bmi = _ida_allins.H8_bmi

H8_bge = _ida_allins.H8_bge

H8_blt = _ida_allins.H8_blt

H8_bgt = _ida_allins.H8_bgt

H8_ble = _ida_allins.H8_ble

H8_bclr = _ida_allins.H8_bclr

H8_biand = _ida_allins.H8_biand

H8_bild = _ida_allins.H8_bild

H8_bior = _ida_allins.H8_bior

H8_bist = _ida_allins.H8_bist

H8_bixor = _ida_allins.H8_bixor

H8_bld = _ida_allins.H8_bld

H8_bnot = _ida_allins.H8_bnot

H8_bor = _ida_allins.H8_bor

H8_bset = _ida_allins.H8_bset

H8_bsr = _ida_allins.H8_bsr

H8_bst = _ida_allins.H8_bst

H8_btst = _ida_allins.H8_btst

H8_bxor = _ida_allins.H8_bxor

H8_clrmac = _ida_allins.H8_clrmac

H8_cmp = _ida_allins.H8_cmp

H8_daa = _ida_allins.H8_daa

H8_das = _ida_allins.H8_das

H8_dec = _ida_allins.H8_dec

H8_divxs = _ida_allins.H8_divxs

H8_divxu = _ida_allins.H8_divxu

H8_eepmov = _ida_allins.H8_eepmov

H8_exts = _ida_allins.H8_exts

H8_extu = _ida_allins.H8_extu

H8_inc = _ida_allins.H8_inc

H8_jmp = _ida_allins.H8_jmp

H8_jsr = _ida_allins.H8_jsr

H8_ldc = _ida_allins.H8_ldc

H8_ldm = _ida_allins.H8_ldm

H8_ldmac = _ida_allins.H8_ldmac

H8_mac = _ida_allins.H8_mac

H8_mov = _ida_allins.H8_mov

H8_movfpe = _ida_allins.H8_movfpe

H8_movtpe = _ida_allins.H8_movtpe

H8_mulxs = _ida_allins.H8_mulxs

H8_mulxu = _ida_allins.H8_mulxu

H8_neg = _ida_allins.H8_neg

H8_nop = _ida_allins.H8_nop

H8_not = _ida_allins.H8_not

H8_or = _ida_allins.H8_or

H8_orc = _ida_allins.H8_orc

H8_pop = _ida_allins.H8_pop

H8_push = _ida_allins.H8_push

H8_rotl = _ida_allins.H8_rotl

H8_rotr = _ida_allins.H8_rotr

H8_rotxl = _ida_allins.H8_rotxl

H8_rotxr = _ida_allins.H8_rotxr

H8_rte = _ida_allins.H8_rte

H8_rts = _ida_allins.H8_rts

H8_shal = _ida_allins.H8_shal

H8_shar = _ida_allins.H8_shar

H8_shll = _ida_allins.H8_shll

H8_shlr = _ida_allins.H8_shlr

H8_sleep = _ida_allins.H8_sleep

H8_stc = _ida_allins.H8_stc

H8_stm = _ida_allins.H8_stm

H8_stmac = _ida_allins.H8_stmac

H8_sub = _ida_allins.H8_sub

H8_subs = _ida_allins.H8_subs

H8_subx = _ida_allins.H8_subx

H8_tas = _ida_allins.H8_tas

H8_trapa = _ida_allins.H8_trapa

H8_xor = _ida_allins.H8_xor

H8_xorc = _ida_allins.H8_xorc

H8_rtel = _ida_allins.H8_rtel

H8_rtsl = _ida_allins.H8_rtsl

H8_movmd = _ida_allins.H8_movmd

H8_movsd = _ida_allins.H8_movsd

H8_bras = _ida_allins.H8_bras

H8_movab = _ida_allins.H8_movab

H8_movaw = _ida_allins.H8_movaw

H8_moval = _ida_allins.H8_moval

H8_bsetne = _ida_allins.H8_bsetne

H8_bseteq = _ida_allins.H8_bseteq

H8_bclrne = _ida_allins.H8_bclrne

H8_bclreq = _ida_allins.H8_bclreq

H8_bstz = _ida_allins.H8_bstz

H8_bistz = _ida_allins.H8_bistz

H8_bfld = _ida_allins.H8_bfld

H8_bfst = _ida_allins.H8_bfst

H8_muls = _ida_allins.H8_muls

H8_divs = _ida_allins.H8_divs

H8_mulu = _ida_allins.H8_mulu

H8_divu = _ida_allins.H8_divu

H8_mulsu = _ida_allins.H8_mulsu

H8_muluu = _ida_allins.H8_muluu

H8_brabc = _ida_allins.H8_brabc

H8_brabs = _ida_allins.H8_brabs

H8_bsrbc = _ida_allins.H8_bsrbc

H8_bsrbs = _ida_allins.H8_bsrbs

H8_last = _ida_allins.H8_last

PIC_null = _ida_allins.PIC_null

PIC_addwf = _ida_allins.PIC_addwf

PIC_andwf = _ida_allins.PIC_andwf

PIC_clrf = _ida_allins.PIC_clrf

PIC_clrw = _ida_allins.PIC_clrw

PIC_comf = _ida_allins.PIC_comf

PIC_decf = _ida_allins.PIC_decf

PIC_decfsz = _ida_allins.PIC_decfsz

PIC_incf = _ida_allins.PIC_incf

PIC_incfsz = _ida_allins.PIC_incfsz

PIC_iorwf = _ida_allins.PIC_iorwf

PIC_movf = _ida_allins.PIC_movf

PIC_movwf = _ida_allins.PIC_movwf

PIC_nop = _ida_allins.PIC_nop

PIC_rlf = _ida_allins.PIC_rlf

PIC_rrf = _ida_allins.PIC_rrf

PIC_subwf = _ida_allins.PIC_subwf

PIC_swapf = _ida_allins.PIC_swapf

PIC_xorwf = _ida_allins.PIC_xorwf

PIC_bcf = _ida_allins.PIC_bcf

PIC_bsf = _ida_allins.PIC_bsf

PIC_btfsc = _ida_allins.PIC_btfsc

PIC_btfss = _ida_allins.PIC_btfss

PIC_addlw = _ida_allins.PIC_addlw

PIC_andlw = _ida_allins.PIC_andlw

PIC_call = _ida_allins.PIC_call

PIC_clrwdt = _ida_allins.PIC_clrwdt

PIC_goto = _ida_allins.PIC_goto

PIC_iorlw = _ida_allins.PIC_iorlw

PIC_movlw = _ida_allins.PIC_movlw

PIC_retfie = _ida_allins.PIC_retfie

PIC_retlw = _ida_allins.PIC_retlw

PIC_return = _ida_allins.PIC_return

PIC_sleep = _ida_allins.PIC_sleep

PIC_sublw = _ida_allins.PIC_sublw

PIC_xorlw = _ida_allins.PIC_xorlw

PIC_option = _ida_allins.PIC_option

PIC_tris = _ida_allins.PIC_tris

PIC_movfw = _ida_allins.PIC_movfw

PIC_tstf = _ida_allins.PIC_tstf

PIC_negf = _ida_allins.PIC_negf

PIC_b = _ida_allins.PIC_b

PIC_clrc = _ida_allins.PIC_clrc

PIC_clrdc = _ida_allins.PIC_clrdc

PIC_clrz = _ida_allins.PIC_clrz

PIC_setc = _ida_allins.PIC_setc

PIC_setdc = _ida_allins.PIC_setdc

PIC_setz = _ida_allins.PIC_setz

PIC_skpc = _ida_allins.PIC_skpc

PIC_skpdc = _ida_allins.PIC_skpdc

PIC_skpnc = _ida_allins.PIC_skpnc

PIC_skpndc = _ida_allins.PIC_skpndc

PIC_skpnz = _ida_allins.PIC_skpnz

PIC_skpz = _ida_allins.PIC_skpz

PIC_bc = _ida_allins.PIC_bc

PIC_bdc = _ida_allins.PIC_bdc

PIC_bnc = _ida_allins.PIC_bnc

PIC_bndc = _ida_allins.PIC_bndc

PIC_bnz = _ida_allins.PIC_bnz

PIC_bz = _ida_allins.PIC_bz

PIC_addcf = _ida_allins.PIC_addcf

PIC_adddcf = _ida_allins.PIC_adddcf

PIC_subcf = _ida_allins.PIC_subcf

PIC_addwf3 = _ida_allins.PIC_addwf3

PIC_addwfc3 = _ida_allins.PIC_addwfc3

PIC_andwf3 = _ida_allins.PIC_andwf3

PIC_clrf2 = _ida_allins.PIC_clrf2

PIC_comf3 = _ida_allins.PIC_comf3

PIC_cpfseq2 = _ida_allins.PIC_cpfseq2

PIC_cpfsgt2 = _ida_allins.PIC_cpfsgt2

PIC_cpfslt2 = _ida_allins.PIC_cpfslt2

PIC_decf3 = _ida_allins.PIC_decf3

PIC_decfsz3 = _ida_allins.PIC_decfsz3

PIC_dcfsnz3 = _ida_allins.PIC_dcfsnz3

PIC_incf3 = _ida_allins.PIC_incf3

PIC_incfsz3 = _ida_allins.PIC_incfsz3

PIC_infsnz3 = _ida_allins.PIC_infsnz3

PIC_iorwf3 = _ida_allins.PIC_iorwf3

PIC_movf3 = _ida_allins.PIC_movf3

PIC_movff2 = _ida_allins.PIC_movff2

PIC_movwf2 = _ida_allins.PIC_movwf2

PIC_mulwf2 = _ida_allins.PIC_mulwf2

PIC_negf2 = _ida_allins.PIC_negf2

PIC_rlcf3 = _ida_allins.PIC_rlcf3

PIC_rlncf3 = _ida_allins.PIC_rlncf3

PIC_rrcf3 = _ida_allins.PIC_rrcf3

PIC_rrncf3 = _ida_allins.PIC_rrncf3

PIC_setf2 = _ida_allins.PIC_setf2

PIC_subfwb3 = _ida_allins.PIC_subfwb3

PIC_subwf3 = _ida_allins.PIC_subwf3

PIC_subwfb3 = _ida_allins.PIC_subwfb3

PIC_swapf3 = _ida_allins.PIC_swapf3

PIC_tstfsz2 = _ida_allins.PIC_tstfsz2

PIC_xorwf3 = _ida_allins.PIC_xorwf3

PIC_bcf3 = _ida_allins.PIC_bcf3

PIC_bsf3 = _ida_allins.PIC_bsf3

PIC_btfsc3 = _ida_allins.PIC_btfsc3

PIC_btfss3 = _ida_allins.PIC_btfss3

PIC_btg3 = _ida_allins.PIC_btg3

PIC_bc1 = _ida_allins.PIC_bc1

PIC_bn1 = _ida_allins.PIC_bn1

PIC_bnc1 = _ida_allins.PIC_bnc1

PIC_bnn1 = _ida_allins.PIC_bnn1

PIC_bnov1 = _ida_allins.PIC_bnov1

PIC_bnz1 = _ida_allins.PIC_bnz1

PIC_bov1 = _ida_allins.PIC_bov1

PIC_bra1 = _ida_allins.PIC_bra1

PIC_bz1 = _ida_allins.PIC_bz1

PIC_call2 = _ida_allins.PIC_call2

PIC_daw0 = _ida_allins.PIC_daw0

PIC_pop0 = _ida_allins.PIC_pop0

PIC_push0 = _ida_allins.PIC_push0

PIC_rcall1 = _ida_allins.PIC_rcall1

PIC_reset0 = _ida_allins.PIC_reset0

PIC_retfie1 = _ida_allins.PIC_retfie1

PIC_return1 = _ida_allins.PIC_return1

PIC_lfsr2 = _ida_allins.PIC_lfsr2

PIC_movlb1 = _ida_allins.PIC_movlb1

PIC_mullw1 = _ida_allins.PIC_mullw1

PIC_tblrd0 = _ida_allins.PIC_tblrd0

PIC_tblrd0p = _ida_allins.PIC_tblrd0p

PIC_tblrd0m = _ida_allins.PIC_tblrd0m

PIC_tblrdp0 = _ida_allins.PIC_tblrdp0

PIC_tblwt0 = _ida_allins.PIC_tblwt0

PIC_tblwt0p = _ida_allins.PIC_tblwt0p

PIC_tblwt0m = _ida_allins.PIC_tblwt0m

PIC_tblwtp0 = _ida_allins.PIC_tblwtp0

PIC_addwfc = _ida_allins.PIC_addwfc

PIC_movlp = _ida_allins.PIC_movlp

PIC_movlb = _ida_allins.PIC_movlb

PIC_addfsr = _ida_allins.PIC_addfsr

PIC_asrf = _ida_allins.PIC_asrf

PIC_lslf = _ida_allins.PIC_lslf

PIC_lsrf = _ida_allins.PIC_lsrf

PIC_subwfb = _ida_allins.PIC_subwfb

PIC_bra = _ida_allins.PIC_bra

PIC_brw = _ida_allins.PIC_brw

PIC_callw = _ida_allins.PIC_callw

PIC_reset = _ida_allins.PIC_reset

PIC_moviw = _ida_allins.PIC_moviw

PIC_movwi = _ida_allins.PIC_movwi

PIC_last = _ida_allins.PIC_last

PIC16_null = _ida_allins.PIC16_null

PIC16_EXCH = _ida_allins.PIC16_EXCH

PIC16_MOV = _ida_allins.PIC16_MOV

PIC16_SWAP = _ida_allins.PIC16_SWAP

PIC16_TBLRDH = _ida_allins.PIC16_TBLRDH

PIC16_TBLRDL = _ida_allins.PIC16_TBLRDL

PIC16_TBLWTH = _ida_allins.PIC16_TBLWTH

PIC16_TBLWTL = _ida_allins.PIC16_TBLWTL

PIC16_MOVPAG = _ida_allins.PIC16_MOVPAG

PIC16_ADD = _ida_allins.PIC16_ADD

PIC16_ADDC = _ida_allins.PIC16_ADDC

PIC16_DAWB = _ida_allins.PIC16_DAWB

PIC16_DEC = _ida_allins.PIC16_DEC

PIC16_DEC2 = _ida_allins.PIC16_DEC2

PIC16_DIV = _ida_allins.PIC16_DIV

PIC16_INC = _ida_allins.PIC16_INC

PIC16_INC2 = _ida_allins.PIC16_INC2

PIC16_MUL = _ida_allins.PIC16_MUL

PIC16_SE = _ida_allins.PIC16_SE

PIC16_SUB = _ida_allins.PIC16_SUB

PIC16_SUBB = _ida_allins.PIC16_SUBB

PIC16_SUBBR = _ida_allins.PIC16_SUBBR

PIC16_SUBR = _ida_allins.PIC16_SUBR

PIC16_ZE = _ida_allins.PIC16_ZE

PIC16_MULW = _ida_allins.PIC16_MULW

PIC16_DIVF = _ida_allins.PIC16_DIVF

PIC16_AND = _ida_allins.PIC16_AND

PIC16_CLR = _ida_allins.PIC16_CLR

PIC16_COM = _ida_allins.PIC16_COM

PIC16_IOR = _ida_allins.PIC16_IOR

PIC16_NEG = _ida_allins.PIC16_NEG

PIC16_SETM = _ida_allins.PIC16_SETM

PIC16_XOR = _ida_allins.PIC16_XOR

PIC16_ASR = _ida_allins.PIC16_ASR

PIC16_LSR = _ida_allins.PIC16_LSR

PIC16_RLC = _ida_allins.PIC16_RLC

PIC16_RLNC = _ida_allins.PIC16_RLNC

PIC16_RRC = _ida_allins.PIC16_RRC

PIC16_RRNC = _ida_allins.PIC16_RRNC

PIC16_SL = _ida_allins.PIC16_SL

PIC16_BCLR = _ida_allins.PIC16_BCLR

PIC16_BSET = _ida_allins.PIC16_BSET

PIC16_BSW = _ida_allins.PIC16_BSW

PIC16_BTG = _ida_allins.PIC16_BTG

PIC16_BTST = _ida_allins.PIC16_BTST

PIC16_BTSTS = _ida_allins.PIC16_BTSTS

PIC16_FBCL = _ida_allins.PIC16_FBCL

PIC16_FF1L = _ida_allins.PIC16_FF1L

PIC16_FF1R = _ida_allins.PIC16_FF1R

PIC16_BTSC = _ida_allins.PIC16_BTSC

PIC16_BTSS = _ida_allins.PIC16_BTSS

PIC16_CP = _ida_allins.PIC16_CP

PIC16_CP0 = _ida_allins.PIC16_CP0

PIC16_CPB = _ida_allins.PIC16_CPB

PIC16_CPSEQ = _ida_allins.PIC16_CPSEQ

PIC16_CPSGT = _ida_allins.PIC16_CPSGT

PIC16_CPSLT = _ida_allins.PIC16_CPSLT

PIC16_CPSNE = _ida_allins.PIC16_CPSNE

PIC16_CPBEQ = _ida_allins.PIC16_CPBEQ

PIC16_CPBNE = _ida_allins.PIC16_CPBNE

PIC16_CPBGT = _ida_allins.PIC16_CPBGT

PIC16_CPBLT = _ida_allins.PIC16_CPBLT

PIC16_BRA = _ida_allins.PIC16_BRA

PIC16_CALL = _ida_allins.PIC16_CALL

PIC16_GOTO = _ida_allins.PIC16_GOTO

PIC16_RCALL = _ida_allins.PIC16_RCALL

PIC16_REPEAT = _ida_allins.PIC16_REPEAT

PIC16_RETFIE = _ida_allins.PIC16_RETFIE

PIC16_RETLW = _ida_allins.PIC16_RETLW

PIC16_RETURN = _ida_allins.PIC16_RETURN

PIC16_DO = _ida_allins.PIC16_DO

PIC16_LNK = _ida_allins.PIC16_LNK

PIC16_POP = _ida_allins.PIC16_POP

PIC16_PUSH = _ida_allins.PIC16_PUSH

PIC16_ULNK = _ida_allins.PIC16_ULNK

PIC16_CLRWDT = _ida_allins.PIC16_CLRWDT

PIC16_DISI = _ida_allins.PIC16_DISI

PIC16_NOP = _ida_allins.PIC16_NOP

PIC16_NOPR = _ida_allins.PIC16_NOPR

PIC16_PWRSAV = _ida_allins.PIC16_PWRSAV

PIC16_RESET = _ida_allins.PIC16_RESET

PIC16_LAC = _ida_allins.PIC16_LAC

PIC16_SAC = _ida_allins.PIC16_SAC

PIC16_SFTAC = _ida_allins.PIC16_SFTAC

PIC16_CLR1 = _ida_allins.PIC16_CLR1

PIC16_ED = _ida_allins.PIC16_ED

PIC16_EDAC = _ida_allins.PIC16_EDAC

PIC16_MAC = _ida_allins.PIC16_MAC

PIC16_MOVSAC = _ida_allins.PIC16_MOVSAC

PIC16_MPY = _ida_allins.PIC16_MPY

PIC16_MSC = _ida_allins.PIC16_MSC

PIC16_BREAK = _ida_allins.PIC16_BREAK

PIC16_URUN = _ida_allins.PIC16_URUN

PIC16_SSTEP = _ida_allins.PIC16_SSTEP

PIC16_FEX = _ida_allins.PIC16_FEX

PIC16_last = _ida_allins.PIC16_last

SPARC_null = _ida_allins.SPARC_null

SPARC_add = _ida_allins.SPARC_add

SPARC_addcc = _ida_allins.SPARC_addcc

SPARC_addc = _ida_allins.SPARC_addc

SPARC_addccc = _ida_allins.SPARC_addccc

SPARC_and = _ida_allins.SPARC_and

SPARC_andcc = _ida_allins.SPARC_andcc

SPARC_andn = _ida_allins.SPARC_andn

SPARC_andncc = _ida_allins.SPARC_andncc

SPARC_b = _ida_allins.SPARC_b

SPARC_bp = _ida_allins.SPARC_bp

SPARC_bpr = _ida_allins.SPARC_bpr

SPARC_call = _ida_allins.SPARC_call

SPARC_casa = _ida_allins.SPARC_casa

SPARC_casxa = _ida_allins.SPARC_casxa

SPARC_done = _ida_allins.SPARC_done

SPARC_fabs = _ida_allins.SPARC_fabs

SPARC_fadd = _ida_allins.SPARC_fadd

SPARC_fbp = _ida_allins.SPARC_fbp

SPARC_fb = _ida_allins.SPARC_fb

SPARC_fcmp = _ida_allins.SPARC_fcmp

SPARC_fcmpe = _ida_allins.SPARC_fcmpe

SPARC_fdiv = _ida_allins.SPARC_fdiv

SPARC_fdmulq = _ida_allins.SPARC_fdmulq

SPARC_flush = _ida_allins.SPARC_flush

SPARC_flushw = _ida_allins.SPARC_flushw

SPARC_fmov = _ida_allins.SPARC_fmov

SPARC_fmovcc = _ida_allins.SPARC_fmovcc

SPARC_fmovr = _ida_allins.SPARC_fmovr

SPARC_fmul = _ida_allins.SPARC_fmul

SPARC_fneg = _ida_allins.SPARC_fneg

SPARC_fsmuld = _ida_allins.SPARC_fsmuld

SPARC_fsqrt = _ida_allins.SPARC_fsqrt

SPARC_fsub = _ida_allins.SPARC_fsub

SPARC_fstox = _ida_allins.SPARC_fstox

SPARC_fdtox = _ida_allins.SPARC_fdtox

SPARC_fqtox = _ida_allins.SPARC_fqtox

SPARC_fxtos = _ida_allins.SPARC_fxtos

SPARC_fxtod = _ida_allins.SPARC_fxtod

SPARC_fxtoq = _ida_allins.SPARC_fxtoq

SPARC_fitos = _ida_allins.SPARC_fitos

SPARC_fdtos = _ida_allins.SPARC_fdtos

SPARC_fqtos = _ida_allins.SPARC_fqtos

SPARC_fitod = _ida_allins.SPARC_fitod

SPARC_fstod = _ida_allins.SPARC_fstod

SPARC_fqtod = _ida_allins.SPARC_fqtod

SPARC_fitoq = _ida_allins.SPARC_fitoq

SPARC_fstoq = _ida_allins.SPARC_fstoq

SPARC_fdtoq = _ida_allins.SPARC_fdtoq

SPARC_fstoi = _ida_allins.SPARC_fstoi

SPARC_fdtoi = _ida_allins.SPARC_fdtoi

SPARC_fqtoi = _ida_allins.SPARC_fqtoi

SPARC_illtrap = _ida_allins.SPARC_illtrap

SPARC_impdep1 = _ida_allins.SPARC_impdep1

SPARC_impdep2 = _ida_allins.SPARC_impdep2

SPARC_jmpl = _ida_allins.SPARC_jmpl

SPARC_ldd = _ida_allins.SPARC_ldd

SPARC_ldda = _ida_allins.SPARC_ldda

SPARC_lddf = _ida_allins.SPARC_lddf

SPARC_lddfa = _ida_allins.SPARC_lddfa

SPARC_ldf = _ida_allins.SPARC_ldf

SPARC_ldfa = _ida_allins.SPARC_ldfa

SPARC_ldfsr = _ida_allins.SPARC_ldfsr

SPARC_ldqf = _ida_allins.SPARC_ldqf

SPARC_ldqfa = _ida_allins.SPARC_ldqfa

SPARC_ldsb = _ida_allins.SPARC_ldsb

SPARC_ldsba = _ida_allins.SPARC_ldsba

SPARC_ldsh = _ida_allins.SPARC_ldsh

SPARC_ldsha = _ida_allins.SPARC_ldsha

SPARC_ldstub = _ida_allins.SPARC_ldstub

SPARC_ldstuba = _ida_allins.SPARC_ldstuba

SPARC_ldsw = _ida_allins.SPARC_ldsw

SPARC_ldswa = _ida_allins.SPARC_ldswa

SPARC_ldub = _ida_allins.SPARC_ldub

SPARC_lduba = _ida_allins.SPARC_lduba

SPARC_lduh = _ida_allins.SPARC_lduh

SPARC_lduha = _ida_allins.SPARC_lduha

SPARC_lduw = _ida_allins.SPARC_lduw

SPARC_lduwa = _ida_allins.SPARC_lduwa

SPARC_ldx = _ida_allins.SPARC_ldx

SPARC_ldxa = _ida_allins.SPARC_ldxa

SPARC_ldxfsr = _ida_allins.SPARC_ldxfsr

SPARC_membar = _ida_allins.SPARC_membar

SPARC_mov = _ida_allins.SPARC_mov

SPARC_movr = _ida_allins.SPARC_movr

SPARC_mulscc = _ida_allins.SPARC_mulscc

SPARC_mulx = _ida_allins.SPARC_mulx

SPARC_nop = _ida_allins.SPARC_nop

SPARC_or = _ida_allins.SPARC_or

SPARC_orcc = _ida_allins.SPARC_orcc

SPARC_orn = _ida_allins.SPARC_orn

SPARC_orncc = _ida_allins.SPARC_orncc

SPARC_popc = _ida_allins.SPARC_popc

SPARC_prefetch = _ida_allins.SPARC_prefetch

SPARC_prefetcha = _ida_allins.SPARC_prefetcha

SPARC_rd = _ida_allins.SPARC_rd

SPARC_rdpr = _ida_allins.SPARC_rdpr

SPARC_restore = _ida_allins.SPARC_restore

SPARC_restored = _ida_allins.SPARC_restored

SPARC_retry = _ida_allins.SPARC_retry

SPARC_return = _ida_allins.SPARC_return

SPARC_save = _ida_allins.SPARC_save

SPARC_saved = _ida_allins.SPARC_saved

SPARC_sdiv = _ida_allins.SPARC_sdiv

SPARC_sdivcc = _ida_allins.SPARC_sdivcc

SPARC_sdivx = _ida_allins.SPARC_sdivx

SPARC_sethi = _ida_allins.SPARC_sethi

SPARC_sir = _ida_allins.SPARC_sir

SPARC_sll = _ida_allins.SPARC_sll

SPARC_sllx = _ida_allins.SPARC_sllx

SPARC_smul = _ida_allins.SPARC_smul

SPARC_smulcc = _ida_allins.SPARC_smulcc

SPARC_sra = _ida_allins.SPARC_sra

SPARC_srax = _ida_allins.SPARC_srax

SPARC_srl = _ida_allins.SPARC_srl

SPARC_srlx = _ida_allins.SPARC_srlx

SPARC_stb = _ida_allins.SPARC_stb

SPARC_stba = _ida_allins.SPARC_stba

SPARC_stbar = _ida_allins.SPARC_stbar

SPARC_std = _ida_allins.SPARC_std

SPARC_stda = _ida_allins.SPARC_stda

SPARC_stdf = _ida_allins.SPARC_stdf

SPARC_stdfa = _ida_allins.SPARC_stdfa

SPARC_stf = _ida_allins.SPARC_stf

SPARC_stfa = _ida_allins.SPARC_stfa

SPARC_stfsr = _ida_allins.SPARC_stfsr

SPARC_sth = _ida_allins.SPARC_sth

SPARC_stha = _ida_allins.SPARC_stha

SPARC_stqf = _ida_allins.SPARC_stqf

SPARC_stqfa = _ida_allins.SPARC_stqfa

SPARC_stw = _ida_allins.SPARC_stw

SPARC_stwa = _ida_allins.SPARC_stwa

SPARC_stx = _ida_allins.SPARC_stx

SPARC_stxa = _ida_allins.SPARC_stxa

SPARC_stxfsr = _ida_allins.SPARC_stxfsr

SPARC_sub = _ida_allins.SPARC_sub

SPARC_subcc = _ida_allins.SPARC_subcc

SPARC_subc = _ida_allins.SPARC_subc

SPARC_subccc = _ida_allins.SPARC_subccc

SPARC_swap = _ida_allins.SPARC_swap

SPARC_swapa = _ida_allins.SPARC_swapa

SPARC_taddcc = _ida_allins.SPARC_taddcc

SPARC_taddcctv = _ida_allins.SPARC_taddcctv

SPARC_tsubcc = _ida_allins.SPARC_tsubcc

SPARC_tsubcctv = _ida_allins.SPARC_tsubcctv

SPARC_t = _ida_allins.SPARC_t

SPARC_udiv = _ida_allins.SPARC_udiv

SPARC_udivcc = _ida_allins.SPARC_udivcc

SPARC_udivx = _ida_allins.SPARC_udivx

SPARC_umul = _ida_allins.SPARC_umul

SPARC_umulcc = _ida_allins.SPARC_umulcc

SPARC_wr = _ida_allins.SPARC_wr

SPARC_wrpr = _ida_allins.SPARC_wrpr

SPARC_xnor = _ida_allins.SPARC_xnor

SPARC_xnorcc = _ida_allins.SPARC_xnorcc

SPARC_xor = _ida_allins.SPARC_xor

SPARC_xorcc = _ida_allins.SPARC_xorcc

SPARC_cmp = _ida_allins.SPARC_cmp

SPARC_jmp = _ida_allins.SPARC_jmp

SPARC_iprefetch = _ida_allins.SPARC_iprefetch

SPARC_tst = _ida_allins.SPARC_tst

SPARC_ret = _ida_allins.SPARC_ret

SPARC_retl = _ida_allins.SPARC_retl

SPARC_setuw = _ida_allins.SPARC_setuw

SPARC_setsw = _ida_allins.SPARC_setsw

SPARC_setx = _ida_allins.SPARC_setx

SPARC_signx = _ida_allins.SPARC_signx

SPARC_not = _ida_allins.SPARC_not

SPARC_neg = _ida_allins.SPARC_neg

SPARC_cas = _ida_allins.SPARC_cas

SPARC_casl = _ida_allins.SPARC_casl

SPARC_casx = _ida_allins.SPARC_casx

SPARC_casxl = _ida_allins.SPARC_casxl

SPARC_inc = _ida_allins.SPARC_inc

SPARC_inccc = _ida_allins.SPARC_inccc

SPARC_dec = _ida_allins.SPARC_dec

SPARC_deccc = _ida_allins.SPARC_deccc

SPARC_btst = _ida_allins.SPARC_btst

SPARC_bset = _ida_allins.SPARC_bset

SPARC_bclr = _ida_allins.SPARC_bclr

SPARC_btog = _ida_allins.SPARC_btog

SPARC_clr = _ida_allins.SPARC_clr

SPARC_clrb = _ida_allins.SPARC_clrb

SPARC_clrh = _ida_allins.SPARC_clrh

SPARC_clrx = _ida_allins.SPARC_clrx

SPARC_clruw = _ida_allins.SPARC_clruw

SPARC_pseudo_mov = _ida_allins.SPARC_pseudo_mov

SPARC_alignaddress = _ida_allins.SPARC_alignaddress

SPARC_array = _ida_allins.SPARC_array

SPARC_edge = _ida_allins.SPARC_edge

SPARC_faligndata = _ida_allins.SPARC_faligndata

SPARC_fandnot1 = _ida_allins.SPARC_fandnot1

SPARC_fandnot2 = _ida_allins.SPARC_fandnot2

SPARC_fand = _ida_allins.SPARC_fand

SPARC_fcmpeq = _ida_allins.SPARC_fcmpeq

SPARC_fcmpgt = _ida_allins.SPARC_fcmpgt

SPARC_fcmple = _ida_allins.SPARC_fcmple

SPARC_fcmpne = _ida_allins.SPARC_fcmpne

SPARC_fexpand = _ida_allins.SPARC_fexpand

SPARC_fmul8sux16 = _ida_allins.SPARC_fmul8sux16

SPARC_fmul8ulx16 = _ida_allins.SPARC_fmul8ulx16

SPARC_fmul8x16 = _ida_allins.SPARC_fmul8x16

SPARC_fmul8x16al = _ida_allins.SPARC_fmul8x16al

SPARC_fmul8x16au = _ida_allins.SPARC_fmul8x16au

SPARC_fmuld8sux16 = _ida_allins.SPARC_fmuld8sux16

SPARC_fmuld8ulx16 = _ida_allins.SPARC_fmuld8ulx16

SPARC_fnand = _ida_allins.SPARC_fnand

SPARC_fnor = _ida_allins.SPARC_fnor

SPARC_fnot1 = _ida_allins.SPARC_fnot1

SPARC_fnot2 = _ida_allins.SPARC_fnot2

SPARC_fone = _ida_allins.SPARC_fone

SPARC_fornot1 = _ida_allins.SPARC_fornot1

SPARC_fornot2 = _ida_allins.SPARC_fornot2

SPARC_for = _ida_allins.SPARC_for

SPARC_fpackfix = _ida_allins.SPARC_fpackfix

SPARC_fpack = _ida_allins.SPARC_fpack

SPARC_fpadd = _ida_allins.SPARC_fpadd

SPARC_fpmerge = _ida_allins.SPARC_fpmerge

SPARC_fpsub = _ida_allins.SPARC_fpsub

SPARC_fsrc1 = _ida_allins.SPARC_fsrc1

SPARC_fsrc2 = _ida_allins.SPARC_fsrc2

SPARC_fxnor = _ida_allins.SPARC_fxnor

SPARC_fxor = _ida_allins.SPARC_fxor

SPARC_fzero = _ida_allins.SPARC_fzero

SPARC_pdist = _ida_allins.SPARC_pdist

SPARC_shutdown = _ida_allins.SPARC_shutdown

SPARC_rett = _ida_allins.SPARC_rett

SPARC_bmask = _ida_allins.SPARC_bmask

SPARC_bshuffle = _ida_allins.SPARC_bshuffle

SPARC_edgen = _ida_allins.SPARC_edgen

SPARC_rdhpr = _ida_allins.SPARC_rdhpr

SPARC_wrhpr = _ida_allins.SPARC_wrhpr

SPARC_siam = _ida_allins.SPARC_siam

SPARC_last = _ida_allins.SPARC_last

HPPA_null = _ida_allins.HPPA_null

HPPA_add = _ida_allins.HPPA_add

HPPA_addb = _ida_allins.HPPA_addb

HPPA_addi = _ida_allins.HPPA_addi

HPPA_addib = _ida_allins.HPPA_addib

HPPA_addil = _ida_allins.HPPA_addil

HPPA_and = _ida_allins.HPPA_and

HPPA_andcm = _ida_allins.HPPA_andcm

HPPA_b = _ida_allins.HPPA_b

HPPA_bb = _ida_allins.HPPA_bb

HPPA_be = _ida_allins.HPPA_be

HPPA_blr = _ida_allins.HPPA_blr

HPPA_break = _ida_allins.HPPA_break

HPPA_bv = _ida_allins.HPPA_bv

HPPA_bve = _ida_allins.HPPA_bve

HPPA_cldd = _ida_allins.HPPA_cldd

HPPA_cldw = _ida_allins.HPPA_cldw

HPPA_clrbts = _ida_allins.HPPA_clrbts

HPPA_cmpb = _ida_allins.HPPA_cmpb

HPPA_cmpclr = _ida_allins.HPPA_cmpclr

HPPA_cmpib = _ida_allins.HPPA_cmpib

HPPA_cmpiclr = _ida_allins.HPPA_cmpiclr

HPPA_copr = _ida_allins.HPPA_copr

HPPA_cstd = _ida_allins.HPPA_cstd

HPPA_cstw = _ida_allins.HPPA_cstw

HPPA_dcor = _ida_allins.HPPA_dcor

HPPA_depd = _ida_allins.HPPA_depd

HPPA_depdi = _ida_allins.HPPA_depdi

HPPA_depw = _ida_allins.HPPA_depw

HPPA_depwi = _ida_allins.HPPA_depwi

HPPA_diag = _ida_allins.HPPA_diag

HPPA_ds = _ida_allins.HPPA_ds

HPPA_extrd = _ida_allins.HPPA_extrd

HPPA_extrw = _ida_allins.HPPA_extrw

HPPA_fdc = _ida_allins.HPPA_fdc

HPPA_fdce = _ida_allins.HPPA_fdce

HPPA_fic = _ida_allins.HPPA_fic

HPPA_fice = _ida_allins.HPPA_fice

HPPA_hadd = _ida_allins.HPPA_hadd

HPPA_havg = _ida_allins.HPPA_havg

HPPA_hshl = _ida_allins.HPPA_hshl

HPPA_hshladd = _ida_allins.HPPA_hshladd

HPPA_hshr = _ida_allins.HPPA_hshr

HPPA_hshradd = _ida_allins.HPPA_hshradd

HPPA_hsub = _ida_allins.HPPA_hsub

HPPA_idtlbt = _ida_allins.HPPA_idtlbt

HPPA_iitlbt = _ida_allins.HPPA_iitlbt

HPPA_lci = _ida_allins.HPPA_lci

HPPA_ldb = _ida_allins.HPPA_ldb

HPPA_ldcd = _ida_allins.HPPA_ldcd

HPPA_ldcw = _ida_allins.HPPA_ldcw

HPPA_ldd = _ida_allins.HPPA_ldd

HPPA_ldda = _ida_allins.HPPA_ldda

HPPA_ldh = _ida_allins.HPPA_ldh

HPPA_ldil = _ida_allins.HPPA_ldil

HPPA_ldo = _ida_allins.HPPA_ldo

HPPA_ldsid = _ida_allins.HPPA_ldsid

HPPA_ldw = _ida_allins.HPPA_ldw

HPPA_ldwa = _ida_allins.HPPA_ldwa

HPPA_lpa = _ida_allins.HPPA_lpa

HPPA_mfctl = _ida_allins.HPPA_mfctl

HPPA_mfia = _ida_allins.HPPA_mfia

HPPA_mfsp = _ida_allins.HPPA_mfsp

HPPA_mixh = _ida_allins.HPPA_mixh

HPPA_mixw = _ida_allins.HPPA_mixw

HPPA_movb = _ida_allins.HPPA_movb

HPPA_movib = _ida_allins.HPPA_movib

HPPA_mtctl = _ida_allins.HPPA_mtctl

HPPA_mtsarcm = _ida_allins.HPPA_mtsarcm

HPPA_mtsm = _ida_allins.HPPA_mtsm

HPPA_mtsp = _ida_allins.HPPA_mtsp

HPPA_or = _ida_allins.HPPA_or

HPPA_pdc = _ida_allins.HPPA_pdc

HPPA_pdtlb = _ida_allins.HPPA_pdtlb

HPPA_pdtlbe = _ida_allins.HPPA_pdtlbe

HPPA_permh = _ida_allins.HPPA_permh

HPPA_pitlb = _ida_allins.HPPA_pitlb

HPPA_pitlbe = _ida_allins.HPPA_pitlbe

HPPA_popbts = _ida_allins.HPPA_popbts

HPPA_probe = _ida_allins.HPPA_probe

HPPA_probei = _ida_allins.HPPA_probei

HPPA_pushbts = _ida_allins.HPPA_pushbts

HPPA_pushnom = _ida_allins.HPPA_pushnom

HPPA_rfi = _ida_allins.HPPA_rfi

HPPA_rsm = _ida_allins.HPPA_rsm

HPPA_shladd = _ida_allins.HPPA_shladd

HPPA_shrpd = _ida_allins.HPPA_shrpd

HPPA_shrpw = _ida_allins.HPPA_shrpw

HPPA_spop0 = _ida_allins.HPPA_spop0

HPPA_spop1 = _ida_allins.HPPA_spop1

HPPA_spop2 = _ida_allins.HPPA_spop2

HPPA_spop3 = _ida_allins.HPPA_spop3

HPPA_ssm = _ida_allins.HPPA_ssm

HPPA_stb = _ida_allins.HPPA_stb

HPPA_stby = _ida_allins.HPPA_stby

HPPA_std = _ida_allins.HPPA_std

HPPA_stda = _ida_allins.HPPA_stda

HPPA_stdby = _ida_allins.HPPA_stdby

HPPA_sth = _ida_allins.HPPA_sth

HPPA_stw = _ida_allins.HPPA_stw

HPPA_stwa = _ida_allins.HPPA_stwa

HPPA_sub = _ida_allins.HPPA_sub

HPPA_subi = _ida_allins.HPPA_subi

HPPA_sync = _ida_allins.HPPA_sync

HPPA_syncdma = _ida_allins.HPPA_syncdma

HPPA_uaddcm = _ida_allins.HPPA_uaddcm

HPPA_uxor = _ida_allins.HPPA_uxor

HPPA_xor = _ida_allins.HPPA_xor

HPPA_fabs = _ida_allins.HPPA_fabs

HPPA_fadd = _ida_allins.HPPA_fadd

HPPA_fcmp = _ida_allins.HPPA_fcmp

HPPA_fcnv = _ida_allins.HPPA_fcnv

HPPA_fcpy = _ida_allins.HPPA_fcpy

HPPA_fdiv = _ida_allins.HPPA_fdiv

HPPA_fid = _ida_allins.HPPA_fid

HPPA_fldd = _ida_allins.HPPA_fldd

HPPA_fldw = _ida_allins.HPPA_fldw

HPPA_fmpy = _ida_allins.HPPA_fmpy

HPPA_fmpyadd = _ida_allins.HPPA_fmpyadd

HPPA_fmpyfadd = _ida_allins.HPPA_fmpyfadd

HPPA_fmpynfadd = _ida_allins.HPPA_fmpynfadd

HPPA_fmpysub = _ida_allins.HPPA_fmpysub

HPPA_fneg = _ida_allins.HPPA_fneg

HPPA_fnegabs = _ida_allins.HPPA_fnegabs

HPPA_frem = _ida_allins.HPPA_frem

HPPA_frnd = _ida_allins.HPPA_frnd

HPPA_fsqrt = _ida_allins.HPPA_fsqrt

HPPA_fstd = _ida_allins.HPPA_fstd

HPPA_fstw = _ida_allins.HPPA_fstw

HPPA_fsub = _ida_allins.HPPA_fsub

HPPA_ftest = _ida_allins.HPPA_ftest

HPPA_xmpyu = _ida_allins.HPPA_xmpyu

HPPA_pmdis = _ida_allins.HPPA_pmdis

HPPA_pmenb = _ida_allins.HPPA_pmenb

HPPA_call = _ida_allins.HPPA_call

HPPA_ret = _ida_allins.HPPA_ret

HPPA_shld = _ida_allins.HPPA_shld

HPPA_shlw = _ida_allins.HPPA_shlw

HPPA_shrd = _ida_allins.HPPA_shrd

HPPA_shrw = _ida_allins.HPPA_shrw

HPPA_ldi = _ida_allins.HPPA_ldi

HPPA_copy = _ida_allins.HPPA_copy

HPPA_mtsar = _ida_allins.HPPA_mtsar

HPPA_nop = _ida_allins.HPPA_nop

HPPA_last = _ida_allins.HPPA_last

H8500_null = _ida_allins.H8500_null

H8500_mov_g = _ida_allins.H8500_mov_g

H8500_mov_e = _ida_allins.H8500_mov_e

H8500_mov_i = _ida_allins.H8500_mov_i

H8500_mov_f = _ida_allins.H8500_mov_f

H8500_mov_l = _ida_allins.H8500_mov_l

H8500_mov_s = _ida_allins.H8500_mov_s

H8500_ldm = _ida_allins.H8500_ldm

H8500_stm = _ida_allins.H8500_stm

H8500_xch = _ida_allins.H8500_xch

H8500_swap = _ida_allins.H8500_swap

H8500_movtpe = _ida_allins.H8500_movtpe

H8500_movfpe = _ida_allins.H8500_movfpe

H8500_add_g = _ida_allins.H8500_add_g

H8500_add_q = _ida_allins.H8500_add_q

H8500_sub = _ida_allins.H8500_sub

H8500_adds = _ida_allins.H8500_adds

H8500_subs = _ida_allins.H8500_subs

H8500_addx = _ida_allins.H8500_addx

H8500_subx = _ida_allins.H8500_subx

H8500_dadd = _ida_allins.H8500_dadd

H8500_dsub = _ida_allins.H8500_dsub

H8500_mulxu = _ida_allins.H8500_mulxu

H8500_divxu = _ida_allins.H8500_divxu

H8500_cmp_g = _ida_allins.H8500_cmp_g

H8500_cmp_e = _ida_allins.H8500_cmp_e

H8500_cmp_i = _ida_allins.H8500_cmp_i

H8500_exts = _ida_allins.H8500_exts

H8500_extu = _ida_allins.H8500_extu

H8500_tst = _ida_allins.H8500_tst

H8500_neg = _ida_allins.H8500_neg

H8500_clr = _ida_allins.H8500_clr

H8500_tas = _ida_allins.H8500_tas

H8500_and = _ida_allins.H8500_and

H8500_or = _ida_allins.H8500_or

H8500_xor = _ida_allins.H8500_xor

H8500_not = _ida_allins.H8500_not

H8500_shal = _ida_allins.H8500_shal

H8500_shar = _ida_allins.H8500_shar

H8500_shll = _ida_allins.H8500_shll

H8500_shlr = _ida_allins.H8500_shlr

H8500_rotl = _ida_allins.H8500_rotl

H8500_rotr = _ida_allins.H8500_rotr

H8500_rotxl = _ida_allins.H8500_rotxl

H8500_rotxr = _ida_allins.H8500_rotxr

H8500_bset = _ida_allins.H8500_bset

H8500_bclr = _ida_allins.H8500_bclr

H8500_bnot = _ida_allins.H8500_bnot

H8500_btst = _ida_allins.H8500_btst

H8500_bra = _ida_allins.H8500_bra

H8500_brn = _ida_allins.H8500_brn

H8500_bhi = _ida_allins.H8500_bhi

H8500_bls = _ida_allins.H8500_bls

H8500_bcc = _ida_allins.H8500_bcc

H8500_bcs = _ida_allins.H8500_bcs

H8500_bne = _ida_allins.H8500_bne

H8500_beq = _ida_allins.H8500_beq

H8500_bvc = _ida_allins.H8500_bvc

H8500_bvs = _ida_allins.H8500_bvs

H8500_bpl = _ida_allins.H8500_bpl

H8500_bmi = _ida_allins.H8500_bmi

H8500_bge = _ida_allins.H8500_bge

H8500_blt = _ida_allins.H8500_blt

H8500_bgt = _ida_allins.H8500_bgt

H8500_ble = _ida_allins.H8500_ble

H8500_jmp = _ida_allins.H8500_jmp

H8500_pjmp = _ida_allins.H8500_pjmp

H8500_bsr = _ida_allins.H8500_bsr

H8500_jsr = _ida_allins.H8500_jsr

H8500_pjsr = _ida_allins.H8500_pjsr

H8500_rts = _ida_allins.H8500_rts

H8500_prts = _ida_allins.H8500_prts

H8500_rtd = _ida_allins.H8500_rtd

H8500_prtd = _ida_allins.H8500_prtd

H8500_scb = _ida_allins.H8500_scb

H8500_trapa = _ida_allins.H8500_trapa

H8500_trap_vs = _ida_allins.H8500_trap_vs

H8500_rte = _ida_allins.H8500_rte

H8500_link = _ida_allins.H8500_link

H8500_unlk = _ida_allins.H8500_unlk

H8500_sleep = _ida_allins.H8500_sleep

H8500_ldc = _ida_allins.H8500_ldc

H8500_stc = _ida_allins.H8500_stc

H8500_andc = _ida_allins.H8500_andc

H8500_orc = _ida_allins.H8500_orc

H8500_xorc = _ida_allins.H8500_xorc

H8500_nop = _ida_allins.H8500_nop

H8500_bpt = _ida_allins.H8500_bpt

H8500_last = _ida_allins.H8500_last

DSP56_null = _ida_allins.DSP56_null

DSP56_abs = _ida_allins.DSP56_abs

DSP56_adc = _ida_allins.DSP56_adc

DSP56_add = _ida_allins.DSP56_add

DSP56_addl = _ida_allins.DSP56_addl

DSP56_addr = _ida_allins.DSP56_addr

DSP56_and = _ida_allins.DSP56_and

DSP56_andi = _ida_allins.DSP56_andi

DSP56_asl = _ida_allins.DSP56_asl

DSP56_asl4 = _ida_allins.DSP56_asl4

DSP56_asr = _ida_allins.DSP56_asr

DSP56_asr4 = _ida_allins.DSP56_asr4

DSP56_asr16 = _ida_allins.DSP56_asr16

DSP56_bfchg = _ida_allins.DSP56_bfchg

DSP56_bfclr = _ida_allins.DSP56_bfclr

DSP56_bfset = _ida_allins.DSP56_bfset

DSP56_bftsth = _ida_allins.DSP56_bftsth

DSP56_bftstl = _ida_allins.DSP56_bftstl

DSP56_bcc = _ida_allins.DSP56_bcc

DSP56_bchg = _ida_allins.DSP56_bchg

DSP56_bclr = _ida_allins.DSP56_bclr

DSP56_bra = _ida_allins.DSP56_bra

DSP56_brclr = _ida_allins.DSP56_brclr

DSP56_brkcc = _ida_allins.DSP56_brkcc

DSP56_brset = _ida_allins.DSP56_brset

DSP56_bscc = _ida_allins.DSP56_bscc

DSP56_bsclr = _ida_allins.DSP56_bsclr

DSP56_bset = _ida_allins.DSP56_bset

DSP56_bsr = _ida_allins.DSP56_bsr

DSP56_bsset = _ida_allins.DSP56_bsset

DSP56_btst = _ida_allins.DSP56_btst

DSP56_chkaau = _ida_allins.DSP56_chkaau

DSP56_clb = _ida_allins.DSP56_clb

DSP56_clr = _ida_allins.DSP56_clr

DSP56_clr24 = _ida_allins.DSP56_clr24

DSP56_cmp = _ida_allins.DSP56_cmp

DSP56_cmpm = _ida_allins.DSP56_cmpm

DSP56_cmpu = _ida_allins.DSP56_cmpu

DSP56_debug = _ida_allins.DSP56_debug

DSP56_debugcc = _ida_allins.DSP56_debugcc

DSP56_dec = _ida_allins.DSP56_dec

DSP56_dec24 = _ida_allins.DSP56_dec24

DSP56_div = _ida_allins.DSP56_div

DSP56_dmac = _ida_allins.DSP56_dmac

DSP56_do = _ida_allins.DSP56_do

DSP56_do_f = _ida_allins.DSP56_do_f

DSP56_dor = _ida_allins.DSP56_dor

DSP56_dor_f = _ida_allins.DSP56_dor_f

DSP56_enddo = _ida_allins.DSP56_enddo

DSP56_eor = _ida_allins.DSP56_eor

DSP56_extract = _ida_allins.DSP56_extract

DSP56_extractu = _ida_allins.DSP56_extractu

DSP56_ext = _ida_allins.DSP56_ext

DSP56_ill = _ida_allins.DSP56_ill

DSP56_imac = _ida_allins.DSP56_imac

DSP56_impy = _ida_allins.DSP56_impy

DSP56_inc = _ida_allins.DSP56_inc

DSP56_inc24 = _ida_allins.DSP56_inc24

DSP56_insert = _ida_allins.DSP56_insert

DSP56_jcc = _ida_allins.DSP56_jcc

DSP56_jclr = _ida_allins.DSP56_jclr

DSP56_jmp = _ida_allins.DSP56_jmp

DSP56_jscc = _ida_allins.DSP56_jscc

DSP56_jsclr = _ida_allins.DSP56_jsclr

DSP56_jset = _ida_allins.DSP56_jset

DSP56_jsr = _ida_allins.DSP56_jsr

DSP56_jsset = _ida_allins.DSP56_jsset

DSP56_lra = _ida_allins.DSP56_lra

DSP56_lsl = _ida_allins.DSP56_lsl

DSP56_lsr = _ida_allins.DSP56_lsr

DSP56_lua = _ida_allins.DSP56_lua

DSP56_lea = _ida_allins.DSP56_lea

DSP56_mac = _ida_allins.DSP56_mac

DSP56_maci = _ida_allins.DSP56_maci

DSP56_mac_s_u = _ida_allins.DSP56_mac_s_u

DSP56_macr = _ida_allins.DSP56_macr

DSP56_macri = _ida_allins.DSP56_macri

DSP56_max = _ida_allins.DSP56_max

DSP56_maxm = _ida_allins.DSP56_maxm

DSP56_merge = _ida_allins.DSP56_merge

DSP56_move = _ida_allins.DSP56_move

DSP56_movec = _ida_allins.DSP56_movec

DSP56_movei = _ida_allins.DSP56_movei

DSP56_movem = _ida_allins.DSP56_movem

DSP56_movep = _ida_allins.DSP56_movep

DSP56_moves = _ida_allins.DSP56_moves

DSP56_mpy = _ida_allins.DSP56_mpy

DSP56_mpyi = _ida_allins.DSP56_mpyi

DSP56_mpy_s_u = _ida_allins.DSP56_mpy_s_u

DSP56_mpyr = _ida_allins.DSP56_mpyr

DSP56_mpyri = _ida_allins.DSP56_mpyri

DSP56_neg = _ida_allins.DSP56_neg

DSP56_negc = _ida_allins.DSP56_negc

DSP56_nop = _ida_allins.DSP56_nop

DSP56_norm = _ida_allins.DSP56_norm

DSP56_normf = _ida_allins.DSP56_normf

DSP56_not = _ida_allins.DSP56_not

DSP56_or = _ida_allins.DSP56_or

DSP56_ori = _ida_allins.DSP56_ori

DSP56_pflush = _ida_allins.DSP56_pflush

DSP56_pflushun = _ida_allins.DSP56_pflushun

DSP56_pfree = _ida_allins.DSP56_pfree

DSP56_plock = _ida_allins.DSP56_plock

DSP56_plockr = _ida_allins.DSP56_plockr

DSP56_punlock = _ida_allins.DSP56_punlock

DSP56_punlockr = _ida_allins.DSP56_punlockr

DSP56_rep = _ida_allins.DSP56_rep

DSP56_repcc = _ida_allins.DSP56_repcc

DSP56_reset = _ida_allins.DSP56_reset

DSP56_rnd = _ida_allins.DSP56_rnd

DSP56_rol = _ida_allins.DSP56_rol

DSP56_ror = _ida_allins.DSP56_ror

DSP56_rti = _ida_allins.DSP56_rti

DSP56_rts = _ida_allins.DSP56_rts

DSP56_sbc = _ida_allins.DSP56_sbc

DSP56_stop = _ida_allins.DSP56_stop

DSP56_sub = _ida_allins.DSP56_sub

DSP56_subl = _ida_allins.DSP56_subl

DSP56_subr = _ida_allins.DSP56_subr

DSP56_swap = _ida_allins.DSP56_swap

DSP56_tcc = _ida_allins.DSP56_tcc

DSP56_tfr = _ida_allins.DSP56_tfr

DSP56_tfr2 = _ida_allins.DSP56_tfr2

DSP56_tfr3 = _ida_allins.DSP56_tfr3

DSP56_trap = _ida_allins.DSP56_trap

DSP56_trapcc = _ida_allins.DSP56_trapcc

DSP56_tst = _ida_allins.DSP56_tst

DSP56_tst2 = _ida_allins.DSP56_tst2

DSP56_vsl = _ida_allins.DSP56_vsl

DSP56_wait = _ida_allins.DSP56_wait

DSP56_zero = _ida_allins.DSP56_zero

DSP56_swi = _ida_allins.DSP56_swi

DSP56_pmov = _ida_allins.DSP56_pmov

DSP56_last = _ida_allins.DSP56_last

DSP96_null = _ida_allins.DSP96_null

DSP96_abs = _ida_allins.DSP96_abs

DSP96_add = _ida_allins.DSP96_add

DSP96_addc = _ida_allins.DSP96_addc

DSP96_and = _ida_allins.DSP96_and

DSP96_andc = _ida_allins.DSP96_andc

DSP96_andi = _ida_allins.DSP96_andi

DSP96_asl = _ida_allins.DSP96_asl

DSP96_asr = _ida_allins.DSP96_asr

DSP96_bcc = _ida_allins.DSP96_bcc

DSP96_bccd = _ida_allins.DSP96_bccd

DSP96_bchg = _ida_allins.DSP96_bchg

DSP96_bclr = _ida_allins.DSP96_bclr

DSP96_bfind = _ida_allins.DSP96_bfind

DSP96_bra = _ida_allins.DSP96_bra

DSP96_brclr = _ida_allins.DSP96_brclr

DSP96_brset = _ida_allins.DSP96_brset

DSP96_bscc = _ida_allins.DSP96_bscc

DSP96_bsccd = _ida_allins.DSP96_bsccd

DSP96_bsclr = _ida_allins.DSP96_bsclr

DSP96_bset = _ida_allins.DSP96_bset

DSP96_bsr = _ida_allins.DSP96_bsr

DSP96_bsrd = _ida_allins.DSP96_bsrd

DSP96_bsset = _ida_allins.DSP96_bsset

DSP96_btst = _ida_allins.DSP96_btst

DSP96_clr = _ida_allins.DSP96_clr

DSP96_cmp = _ida_allins.DSP96_cmp

DSP96_cmpg = _ida_allins.DSP96_cmpg

DSP96_debugcc = _ida_allins.DSP96_debugcc

DSP96_dec = _ida_allins.DSP96_dec

DSP96_do = _ida_allins.DSP96_do

DSP96_dor = _ida_allins.DSP96_dor

DSP96_enddo = _ida_allins.DSP96_enddo

DSP96_eor = _ida_allins.DSP96_eor

DSP96_ext = _ida_allins.DSP96_ext

DSP96_extb = _ida_allins.DSP96_extb

DSP96_fabs = _ida_allins.DSP96_fabs

DSP96_fadd = _ida_allins.DSP96_fadd

DSP96_faddsub = _ida_allins.DSP96_faddsub

DSP96_fbcc = _ida_allins.DSP96_fbcc

DSP96_fbccd = _ida_allins.DSP96_fbccd

DSP96_fbscc = _ida_allins.DSP96_fbscc

DSP96_fbsccd = _ida_allins.DSP96_fbsccd

DSP96_fclr = _ida_allins.DSP96_fclr

DSP96_fcmp = _ida_allins.DSP96_fcmp

DSP96_fcmpg = _ida_allins.DSP96_fcmpg

DSP96_fcmpm = _ida_allins.DSP96_fcmpm

DSP96_fcopys = _ida_allins.DSP96_fcopys

DSP96_fdebugcc = _ida_allins.DSP96_fdebugcc

DSP96_fgetman = _ida_allins.DSP96_fgetman

DSP96_fint = _ida_allins.DSP96_fint

DSP96_fjcc = _ida_allins.DSP96_fjcc

DSP96_fjccd = _ida_allins.DSP96_fjccd

DSP96_fjscc = _ida_allins.DSP96_fjscc

DSP96_fjsccd = _ida_allins.DSP96_fjsccd

DSP96_float = _ida_allins.DSP96_float

DSP96_floatu = _ida_allins.DSP96_floatu

DSP96_floor = _ida_allins.DSP96_floor

DSP96_fmove = _ida_allins.DSP96_fmove

DSP96_fmpyfadd = _ida_allins.DSP96_fmpyfadd

DSP96_fmpyfaddsub = _ida_allins.DSP96_fmpyfaddsub

DSP96_fmpyfsub = _ida_allins.DSP96_fmpyfsub

DSP96_fmpy = _ida_allins.DSP96_fmpy

DSP96_fneg = _ida_allins.DSP96_fneg

DSP96_fscale = _ida_allins.DSP96_fscale

DSP96_fseedd = _ida_allins.DSP96_fseedd

DSP96_fseedr = _ida_allins.DSP96_fseedr

DSP96_fsub = _ida_allins.DSP96_fsub

DSP96_ftfr = _ida_allins.DSP96_ftfr

DSP96_ftrapcc = _ida_allins.DSP96_ftrapcc

DSP96_ftst = _ida_allins.DSP96_ftst

DSP96_getexp = _ida_allins.DSP96_getexp

DSP96_illegal = _ida_allins.DSP96_illegal

DSP96_inc = _ida_allins.DSP96_inc

DSP96_int = _ida_allins.DSP96_int

DSP96_intrz = _ida_allins.DSP96_intrz

DSP96_intu = _ida_allins.DSP96_intu

DSP96_inturz = _ida_allins.DSP96_inturz

DSP96_jcc = _ida_allins.DSP96_jcc

DSP96_jccd = _ida_allins.DSP96_jccd

DSP96_jclr = _ida_allins.DSP96_jclr

DSP96_join = _ida_allins.DSP96_join

DSP96_joinb = _ida_allins.DSP96_joinb

DSP96_jscc = _ida_allins.DSP96_jscc

DSP96_jsccd = _ida_allins.DSP96_jsccd

DSP96_jsclr = _ida_allins.DSP96_jsclr

DSP96_jset = _ida_allins.DSP96_jset

DSP96_jsset = _ida_allins.DSP96_jsset

DSP96_lea = _ida_allins.DSP96_lea

DSP96_lra = _ida_allins.DSP96_lra

DSP96_lsl = _ida_allins.DSP96_lsl

DSP96_lsr = _ida_allins.DSP96_lsr

DSP96_move = _ida_allins.DSP96_move

DSP96_movec = _ida_allins.DSP96_movec

DSP96_movei = _ida_allins.DSP96_movei

DSP96_movem = _ida_allins.DSP96_movem

DSP96_movep = _ida_allins.DSP96_movep

DSP96_moves = _ida_allins.DSP96_moves

DSP96_moveta = _ida_allins.DSP96_moveta

DSP96_mpys = _ida_allins.DSP96_mpys

DSP96_mpyu = _ida_allins.DSP96_mpyu

DSP96_neg = _ida_allins.DSP96_neg

DSP96_negc = _ida_allins.DSP96_negc

DSP96_nop = _ida_allins.DSP96_nop

DSP96_not = _ida_allins.DSP96_not

DSP96_or = _ida_allins.DSP96_or

DSP96_orc = _ida_allins.DSP96_orc

DSP96_ori = _ida_allins.DSP96_ori

DSP96_rep = _ida_allins.DSP96_rep

DSP96_reset = _ida_allins.DSP96_reset

DSP96_rol = _ida_allins.DSP96_rol

DSP96_ror = _ida_allins.DSP96_ror

DSP96_rti = _ida_allins.DSP96_rti

DSP96_rtr = _ida_allins.DSP96_rtr

DSP96_rts = _ida_allins.DSP96_rts

DSP96_setw = _ida_allins.DSP96_setw

DSP96_split = _ida_allins.DSP96_split

DSP96_splitb = _ida_allins.DSP96_splitb

DSP96_stop = _ida_allins.DSP96_stop

DSP96_sub = _ida_allins.DSP96_sub

DSP96_subc = _ida_allins.DSP96_subc

DSP96_tfr = _ida_allins.DSP96_tfr

DSP96_trapcc = _ida_allins.DSP96_trapcc

DSP96_tst = _ida_allins.DSP96_tst

DSP96_wait = _ida_allins.DSP96_wait

DSP96_last = _ida_allins.DSP96_last

PM96_NoMove = _ida_allins.PM96_NoMove

PM96_R2R = _ida_allins.PM96_R2R

PM96_Update = _ida_allins.PM96_Update

PM96_XYMem = _ida_allins.PM96_XYMem

PM96_XYmemR = _ida_allins.PM96_XYmemR

PM96_Long = _ida_allins.PM96_Long

PM96_XY = _ida_allins.PM96_XY

PM96_IFcc = _ida_allins.PM96_IFcc

C166_null = _ida_allins.C166_null

C166_add = _ida_allins.C166_add

C166_addb = _ida_allins.C166_addb

C166_addc = _ida_allins.C166_addc

C166_addcb = _ida_allins.C166_addcb

C166_and = _ida_allins.C166_and

C166_andb = _ida_allins.C166_andb

C166_ashr = _ida_allins.C166_ashr

C166_atomic = _ida_allins.C166_atomic

C166_band = _ida_allins.C166_band

C166_bclr = _ida_allins.C166_bclr

C166_bcmp = _ida_allins.C166_bcmp

C166_bfldh = _ida_allins.C166_bfldh

C166_bfldl = _ida_allins.C166_bfldl

C166_bmov = _ida_allins.C166_bmov

C166_bmovn = _ida_allins.C166_bmovn

C166_bor = _ida_allins.C166_bor

C166_bset = _ida_allins.C166_bset

C166_bxor = _ida_allins.C166_bxor

C166_calla = _ida_allins.C166_calla

C166_calli = _ida_allins.C166_calli

C166_callr = _ida_allins.C166_callr

C166_calls = _ida_allins.C166_calls

C166_cmp = _ida_allins.C166_cmp

C166_cmpb = _ida_allins.C166_cmpb

C166_cmpd1 = _ida_allins.C166_cmpd1

C166_cmpd2 = _ida_allins.C166_cmpd2

C166_cmpi1 = _ida_allins.C166_cmpi1

C166_cmpi2 = _ida_allins.C166_cmpi2

C166_cpl = _ida_allins.C166_cpl

C166_cplb = _ida_allins.C166_cplb

C166_diswdt = _ida_allins.C166_diswdt

C166_div = _ida_allins.C166_div

C166_divl = _ida_allins.C166_divl

C166_divlu = _ida_allins.C166_divlu

C166_divu = _ida_allins.C166_divu

C166_einit = _ida_allins.C166_einit

C166_extr = _ida_allins.C166_extr

C166_extp = _ida_allins.C166_extp

C166_extpr = _ida_allins.C166_extpr

C166_exts = _ida_allins.C166_exts

C166_extsr = _ida_allins.C166_extsr

C166_idle = _ida_allins.C166_idle

C166_jb = _ida_allins.C166_jb

C166_jbc = _ida_allins.C166_jbc

C166_jmpa = _ida_allins.C166_jmpa

C166_jmpi = _ida_allins.C166_jmpi

C166_jmpr = _ida_allins.C166_jmpr

C166_jmps = _ida_allins.C166_jmps

C166_jnb = _ida_allins.C166_jnb

C166_jnbs = _ida_allins.C166_jnbs

C166_mov = _ida_allins.C166_mov

C166_movb = _ida_allins.C166_movb

C166_movbs = _ida_allins.C166_movbs

C166_movbz = _ida_allins.C166_movbz

C166_mul = _ida_allins.C166_mul

C166_mulu = _ida_allins.C166_mulu

C166_neg = _ida_allins.C166_neg

C166_negb = _ida_allins.C166_negb

C166_nop = _ida_allins.C166_nop

C166_or = _ida_allins.C166_or

C166_orb = _ida_allins.C166_orb

C166_pcall = _ida_allins.C166_pcall

C166_pop = _ida_allins.C166_pop

C166_prior = _ida_allins.C166_prior

C166_push = _ida_allins.C166_push

C166_pwrdn = _ida_allins.C166_pwrdn

C166_ret = _ida_allins.C166_ret

C166_reti = _ida_allins.C166_reti

C166_retp = _ida_allins.C166_retp

C166_rets = _ida_allins.C166_rets

C166_rol = _ida_allins.C166_rol

C166_ror = _ida_allins.C166_ror

C166_scxt = _ida_allins.C166_scxt

C166_shl = _ida_allins.C166_shl

C166_shr = _ida_allins.C166_shr

C166_srst = _ida_allins.C166_srst

C166_srvwdt = _ida_allins.C166_srvwdt

C166_sub = _ida_allins.C166_sub

C166_subb = _ida_allins.C166_subb

C166_subc = _ida_allins.C166_subc

C166_subcb = _ida_allins.C166_subcb

C166_trap = _ida_allins.C166_trap

C166_xor = _ida_allins.C166_xor

C166_xorb = _ida_allins.C166_xorb

ST10_CoABS = _ida_allins.ST10_CoABS

ST10_CoADD = _ida_allins.ST10_CoADD

ST10_CoASHR = _ida_allins.ST10_CoASHR

ST10_CoCMP = _ida_allins.ST10_CoCMP

ST10_CoLOAD = _ida_allins.ST10_CoLOAD

ST10_CoMAC = _ida_allins.ST10_CoMAC

ST10_CoMACM = _ida_allins.ST10_CoMACM

ST10_CoMAX = _ida_allins.ST10_CoMAX

ST10_CoMIN = _ida_allins.ST10_CoMIN

ST10_CoMOV = _ida_allins.ST10_CoMOV

ST10_CoMUL = _ida_allins.ST10_CoMUL

ST10_CoNEG = _ida_allins.ST10_CoNEG

ST10_CoNOP = _ida_allins.ST10_CoNOP

ST10_CoRND = _ida_allins.ST10_CoRND

ST10_CoSHL = _ida_allins.ST10_CoSHL

ST10_CoSHR = _ida_allins.ST10_CoSHR

ST10_CoSTORE = _ida_allins.ST10_CoSTORE

ST10_CoSUB = _ida_allins.ST10_CoSUB

C166_enwdt = _ida_allins.C166_enwdt

C166_sbrk = _ida_allins.C166_sbrk

C166_last = _ida_allins.C166_last

ST20_null = _ida_allins.ST20_null

ST20_adc = _ida_allins.ST20_adc

ST20_add = _ida_allins.ST20_add

ST20_addc = _ida_allins.ST20_addc

ST20_ajw = _ida_allins.ST20_ajw

ST20_and = _ida_allins.ST20_and

ST20_arot = _ida_allins.ST20_arot

ST20_ashr = _ida_allins.ST20_ashr

ST20_biquad = _ida_allins.ST20_biquad

ST20_bitld = _ida_allins.ST20_bitld

ST20_bitmask = _ida_allins.ST20_bitmask

ST20_bitst = _ida_allins.ST20_bitst

ST20_breakpoint = _ida_allins.ST20_breakpoint

ST20_cj = _ida_allins.ST20_cj

ST20_dequeue = _ida_allins.ST20_dequeue

ST20_divstep = _ida_allins.ST20_divstep

ST20_dup = _ida_allins.ST20_dup

ST20_ecall = _ida_allins.ST20_ecall

ST20_enqueue = _ida_allins.ST20_enqueue

ST20_eqc = _ida_allins.ST20_eqc

ST20_eret = _ida_allins.ST20_eret

ST20_fcall = _ida_allins.ST20_fcall

ST20_gajw = _ida_allins.ST20_gajw

ST20_gt = _ida_allins.ST20_gt

ST20_gtu = _ida_allins.ST20_gtu

ST20_io = _ida_allins.ST20_io

ST20_j = _ida_allins.ST20_j

ST20_jab = _ida_allins.ST20_jab

ST20_lbinc = _ida_allins.ST20_lbinc

ST20_ldc = _ida_allins.ST20_ldc

ST20_ldl = _ida_allins.ST20_ldl

ST20_ldlp = _ida_allins.ST20_ldlp

ST20_ldnl = _ida_allins.ST20_ldnl

ST20_ldnlp = _ida_allins.ST20_ldnlp

ST20_ldpi = _ida_allins.ST20_ldpi

ST20_ldprodid = _ida_allins.ST20_ldprodid

ST20_ldtdesc = _ida_allins.ST20_ldtdesc

ST20_lsinc = _ida_allins.ST20_lsinc

ST20_lsxinc = _ida_allins.ST20_lsxinc

ST20_lwinc = _ida_allins.ST20_lwinc

ST20_mac = _ida_allins.ST20_mac

ST20_mul = _ida_allins.ST20_mul

ST20_nfix = _ida_allins.ST20_nfix

ST20_nop = _ida_allins.ST20_nop

ST20_not = _ida_allins.ST20_not

ST20_opr = _ida_allins.ST20_opr

ST20_or = _ida_allins.ST20_or

ST20_order = _ida_allins.ST20_order

ST20_orderu = _ida_allins.ST20_orderu

ST20_pfix = _ida_allins.ST20_pfix

ST20_rev = _ida_allins.ST20_rev

ST20_rmw = _ida_allins.ST20_rmw

ST20_rot = _ida_allins.ST20_rot

ST20_run = _ida_allins.ST20_run

ST20_saturate = _ida_allins.ST20_saturate

ST20_sbinc = _ida_allins.ST20_sbinc

ST20_shl = _ida_allins.ST20_shl

ST20_shr = _ida_allins.ST20_shr

ST20_signal = _ida_allins.ST20_signal

ST20_smacinit = _ida_allins.ST20_smacinit

ST20_smacloop = _ida_allins.ST20_smacloop

ST20_smul = _ida_allins.ST20_smul

ST20_ssinc = _ida_allins.ST20_ssinc

ST20_statusclr = _ida_allins.ST20_statusclr

ST20_statusset = _ida_allins.ST20_statusset

ST20_statustst = _ida_allins.ST20_statustst

ST20_stl = _ida_allins.ST20_stl

ST20_stnl = _ida_allins.ST20_stnl

ST20_stop = _ida_allins.ST20_stop

ST20_sub = _ida_allins.ST20_sub

ST20_subc = _ida_allins.ST20_subc

ST20_swap32 = _ida_allins.ST20_swap32

ST20_swinc = _ida_allins.ST20_swinc

ST20_timeslice = _ida_allins.ST20_timeslice

ST20_umac = _ida_allins.ST20_umac

ST20_unsign = _ida_allins.ST20_unsign

ST20_wait = _ida_allins.ST20_wait

ST20_wsub = _ida_allins.ST20_wsub

ST20_xbword = _ida_allins.ST20_xbword

ST20_xor = _ida_allins.ST20_xor

ST20_xsword = _ida_allins.ST20_xsword

ST20_alt = _ida_allins.ST20_alt

ST20_altend = _ida_allins.ST20_altend

ST20_altwt = _ida_allins.ST20_altwt

ST20_bcnt = _ida_allins.ST20_bcnt

ST20_bitcnt = _ida_allins.ST20_bitcnt

ST20_bitrevnbits = _ida_allins.ST20_bitrevnbits

ST20_bitrevword = _ida_allins.ST20_bitrevword

ST20_bsub = _ida_allins.ST20_bsub

ST20_call = _ida_allins.ST20_call

ST20_causeerror = _ida_allins.ST20_causeerror

ST20_cb = _ida_allins.ST20_cb

ST20_cbu = _ida_allins.ST20_cbu

ST20_ccnt1 = _ida_allins.ST20_ccnt1

ST20_cflerr = _ida_allins.ST20_cflerr

ST20_cir = _ida_allins.ST20_cir

ST20_ciru = _ida_allins.ST20_ciru

ST20_clockdis = _ida_allins.ST20_clockdis

ST20_clockenb = _ida_allins.ST20_clockenb

ST20_clrhalterr = _ida_allins.ST20_clrhalterr

ST20_crcbyte = _ida_allins.ST20_crcbyte

ST20_crcword = _ida_allins.ST20_crcword

ST20_cs = _ida_allins.ST20_cs

ST20_csngl = _ida_allins.ST20_csngl

ST20_csu = _ida_allins.ST20_csu

ST20_csub0 = _ida_allins.ST20_csub0

ST20_cword = _ida_allins.ST20_cword

ST20_devlb = _ida_allins.ST20_devlb

ST20_devls = _ida_allins.ST20_devls

ST20_devlw = _ida_allins.ST20_devlw

ST20_devmove = _ida_allins.ST20_devmove

ST20_devsb = _ida_allins.ST20_devsb

ST20_devss = _ida_allins.ST20_devss

ST20_devsw = _ida_allins.ST20_devsw

ST20_diff = _ida_allins.ST20_diff

ST20_disc = _ida_allins.ST20_disc

ST20_diss = _ida_allins.ST20_diss

ST20_dist = _ida_allins.ST20_dist

ST20_div = _ida_allins.ST20_div

ST20_enbc = _ida_allins.ST20_enbc

ST20_enbs = _ida_allins.ST20_enbs

ST20_enbt = _ida_allins.ST20_enbt

ST20_endp = _ida_allins.ST20_endp

ST20_fmul = _ida_allins.ST20_fmul

ST20_fptesterr = _ida_allins.ST20_fptesterr

ST20_gcall = _ida_allins.ST20_gcall

ST20_gintdis = _ida_allins.ST20_gintdis

ST20_gintenb = _ida_allins.ST20_gintenb

ST20_in = _ida_allins.ST20_in

ST20_insertqueue = _ida_allins.ST20_insertqueue

ST20_intdis = _ida_allins.ST20_intdis

ST20_intenb = _ida_allins.ST20_intenb

ST20_iret = _ida_allins.ST20_iret

ST20_ladd = _ida_allins.ST20_ladd

ST20_lb = _ida_allins.ST20_lb

ST20_lbx = _ida_allins.ST20_lbx

ST20_ldclock = _ida_allins.ST20_ldclock

ST20_lddevid = _ida_allins.ST20_lddevid

ST20_ldiff = _ida_allins.ST20_ldiff

ST20_ldinf = _ida_allins.ST20_ldinf

ST20_ldiv = _ida_allins.ST20_ldiv

ST20_ldmemstartval = _ida_allins.ST20_ldmemstartval

ST20_ldpri = _ida_allins.ST20_ldpri

ST20_ldshadow = _ida_allins.ST20_ldshadow

ST20_ldtimer = _ida_allins.ST20_ldtimer

ST20_ldtraph = _ida_allins.ST20_ldtraph

ST20_ldtrapped = _ida_allins.ST20_ldtrapped

ST20_lend = _ida_allins.ST20_lend

ST20_lmul = _ida_allins.ST20_lmul

ST20_ls = _ida_allins.ST20_ls

ST20_lshl = _ida_allins.ST20_lshl

ST20_lshr = _ida_allins.ST20_lshr

ST20_lsub = _ida_allins.ST20_lsub

ST20_lsum = _ida_allins.ST20_lsum

ST20_lsx = _ida_allins.ST20_lsx

ST20_mint = _ida_allins.ST20_mint

ST20_move = _ida_allins.ST20_move

ST20_move2dall = _ida_allins.ST20_move2dall

ST20_move2dinit = _ida_allins.ST20_move2dinit

ST20_move2dnonzero = _ida_allins.ST20_move2dnonzero

ST20_move2dzero = _ida_allins.ST20_move2dzero

ST20_norm = _ida_allins.ST20_norm

ST20_out = _ida_allins.ST20_out

ST20_outbyte = _ida_allins.ST20_outbyte

ST20_outword = _ida_allins.ST20_outword

ST20_pop = _ida_allins.ST20_pop

ST20_postnormsn = _ida_allins.ST20_postnormsn

ST20_prod = _ida_allins.ST20_prod

ST20_reboot = _ida_allins.ST20_reboot

ST20_rem = _ida_allins.ST20_rem

ST20_resetch = _ida_allins.ST20_resetch

ST20_restart = _ida_allins.ST20_restart

ST20_ret = _ida_allins.ST20_ret

ST20_roundsn = _ida_allins.ST20_roundsn

ST20_runp = _ida_allins.ST20_runp

ST20_satadd = _ida_allins.ST20_satadd

ST20_satmul = _ida_allins.ST20_satmul

ST20_satsub = _ida_allins.ST20_satsub

ST20_saveh = _ida_allins.ST20_saveh

ST20_savel = _ida_allins.ST20_savel

ST20_sb = _ida_allins.ST20_sb

ST20_seterr = _ida_allins.ST20_seterr

ST20_sethalterr = _ida_allins.ST20_sethalterr

ST20_settimeslice = _ida_allins.ST20_settimeslice

ST20_slmul = _ida_allins.ST20_slmul

ST20_ss = _ida_allins.ST20_ss

ST20_ssub = _ida_allins.ST20_ssub

ST20_startp = _ida_allins.ST20_startp

ST20_stclock = _ida_allins.ST20_stclock

ST20_sthb = _ida_allins.ST20_sthb

ST20_sthf = _ida_allins.ST20_sthf

ST20_stlb = _ida_allins.ST20_stlb

ST20_stlf = _ida_allins.ST20_stlf

ST20_stoperr = _ida_allins.ST20_stoperr

ST20_stopp = _ida_allins.ST20_stopp

ST20_stshadow = _ida_allins.ST20_stshadow

ST20_sttimer = _ida_allins.ST20_sttimer

ST20_sttraph = _ida_allins.ST20_sttraph

ST20_sttrapped = _ida_allins.ST20_sttrapped

ST20_sulmul = _ida_allins.ST20_sulmul

ST20_sum = _ida_allins.ST20_sum

ST20_swapqueue = _ida_allins.ST20_swapqueue

ST20_swaptimer = _ida_allins.ST20_swaptimer

ST20_talt = _ida_allins.ST20_talt

ST20_taltwt = _ida_allins.ST20_taltwt

ST20_testerr = _ida_allins.ST20_testerr

ST20_testhalterr = _ida_allins.ST20_testhalterr

ST20_testpranal = _ida_allins.ST20_testpranal

ST20_tin = _ida_allins.ST20_tin

ST20_trapdis = _ida_allins.ST20_trapdis

ST20_trapenb = _ida_allins.ST20_trapenb

ST20_tret = _ida_allins.ST20_tret

ST20_unpacksn = _ida_allins.ST20_unpacksn

ST20_wcnt = _ida_allins.ST20_wcnt

ST20_wsubdb = _ida_allins.ST20_wsubdb

ST20_xdble = _ida_allins.ST20_xdble

ST20_xword = _ida_allins.ST20_xword

ST20_last = _ida_allins.ST20_last

ST7_null = _ida_allins.ST7_null

ST7_adc = _ida_allins.ST7_adc

ST7_add = _ida_allins.ST7_add

ST7_and = _ida_allins.ST7_and

ST7_bcp = _ida_allins.ST7_bcp

ST7_bres = _ida_allins.ST7_bres

ST7_bset = _ida_allins.ST7_bset

ST7_btjf = _ida_allins.ST7_btjf

ST7_btjt = _ida_allins.ST7_btjt

ST7_call = _ida_allins.ST7_call

ST7_callr = _ida_allins.ST7_callr

ST7_clr = _ida_allins.ST7_clr

ST7_cp = _ida_allins.ST7_cp

ST7_cpl = _ida_allins.ST7_cpl

ST7_dec = _ida_allins.ST7_dec

ST7_halt = _ida_allins.ST7_halt

ST7_iret = _ida_allins.ST7_iret

ST7_inc = _ida_allins.ST7_inc

ST7_jp = _ida_allins.ST7_jp

ST7_jra = _ida_allins.ST7_jra

ST7_jrt = _ida_allins.ST7_jrt

ST7_jrf = _ida_allins.ST7_jrf

ST7_jrih = _ida_allins.ST7_jrih

ST7_jril = _ida_allins.ST7_jril

ST7_jrh = _ida_allins.ST7_jrh

ST7_jrnh = _ida_allins.ST7_jrnh

ST7_jrm = _ida_allins.ST7_jrm

ST7_jrnm = _ida_allins.ST7_jrnm

ST7_jrmi = _ida_allins.ST7_jrmi

ST7_jrpl = _ida_allins.ST7_jrpl

ST7_jreq = _ida_allins.ST7_jreq

ST7_jrne = _ida_allins.ST7_jrne

ST7_jrc = _ida_allins.ST7_jrc

ST7_jrnc = _ida_allins.ST7_jrnc

ST7_jrult = _ida_allins.ST7_jrult

ST7_jruge = _ida_allins.ST7_jruge

ST7_jrugt = _ida_allins.ST7_jrugt

ST7_jrule = _ida_allins.ST7_jrule

ST7_ld = _ida_allins.ST7_ld

ST7_mul = _ida_allins.ST7_mul

ST7_neg = _ida_allins.ST7_neg

ST7_nop = _ida_allins.ST7_nop

ST7_or = _ida_allins.ST7_or

ST7_pop = _ida_allins.ST7_pop

ST7_push = _ida_allins.ST7_push

ST7_rcf = _ida_allins.ST7_rcf

ST7_ret = _ida_allins.ST7_ret

ST7_rim = _ida_allins.ST7_rim

ST7_rlc = _ida_allins.ST7_rlc

ST7_rrc = _ida_allins.ST7_rrc

ST7_rsp = _ida_allins.ST7_rsp

ST7_sbc = _ida_allins.ST7_sbc

ST7_scf = _ida_allins.ST7_scf

ST7_sim = _ida_allins.ST7_sim

ST7_sla = _ida_allins.ST7_sla

ST7_sll = _ida_allins.ST7_sll

ST7_srl = _ida_allins.ST7_srl

ST7_sra = _ida_allins.ST7_sra

ST7_sub = _ida_allins.ST7_sub

ST7_swap = _ida_allins.ST7_swap

ST7_tnz = _ida_allins.ST7_tnz

ST7_trap = _ida_allins.ST7_trap

ST7_wfi = _ida_allins.ST7_wfi

ST7_xor = _ida_allins.ST7_xor

ST7_last = _ida_allins.ST7_last

IA64_null = _ida_allins.IA64_null

IA64_0 = _ida_allins.IA64_0

IA64_1 = _ida_allins.IA64_1

IA64_a = _ida_allins.IA64_a

IA64_acq = _ida_allins.IA64_acq

IA64_add = _ida_allins.IA64_add

IA64_addl = _ida_allins.IA64_addl

IA64_addp4 = _ida_allins.IA64_addp4

IA64_adds = _ida_allins.IA64_adds

IA64_alloc = _ida_allins.IA64_alloc

IA64_and = _ida_allins.IA64_and

IA64_andcm = _ida_allins.IA64_andcm

IA64_b = _ida_allins.IA64_b

IA64_bias = _ida_allins.IA64_bias

IA64_br = _ida_allins.IA64_br

IA64_break = _ida_allins.IA64_break

IA64_brl = _ida_allins.IA64_brl

IA64_brp = _ida_allins.IA64_brp

IA64_bsw = _ida_allins.IA64_bsw

IA64_c = _ida_allins.IA64_c

IA64_call = _ida_allins.IA64_call

IA64_cexit = _ida_allins.IA64_cexit

IA64_chk = _ida_allins.IA64_chk

IA64_cloop = _ida_allins.IA64_cloop

IA64_clr = _ida_allins.IA64_clr

IA64_clrrrb = _ida_allins.IA64_clrrrb

IA64_cmp = _ida_allins.IA64_cmp

IA64_cmp4 = _ida_allins.IA64_cmp4

IA64_cmpxchg1 = _ida_allins.IA64_cmpxchg1

IA64_cmpxchg2 = _ida_allins.IA64_cmpxchg2

IA64_cmpxchg4 = _ida_allins.IA64_cmpxchg4

IA64_cmpxchg8 = _ida_allins.IA64_cmpxchg8

IA64_cond = _ida_allins.IA64_cond

IA64_cover = _ida_allins.IA64_cover

IA64_ctop = _ida_allins.IA64_ctop

IA64_czx1 = _ida_allins.IA64_czx1

IA64_czx2 = _ida_allins.IA64_czx2

IA64_d = _ida_allins.IA64_d

IA64_dep = _ida_allins.IA64_dep

IA64_dpnt = _ida_allins.IA64_dpnt

IA64_dptk = _ida_allins.IA64_dptk

IA64_e = _ida_allins.IA64_e

IA64_epc = _ida_allins.IA64_epc

IA64_eq = _ida_allins.IA64_eq

IA64_excl = _ida_allins.IA64_excl

IA64_exit = _ida_allins.IA64_exit

IA64_exp = _ida_allins.IA64_exp

IA64_extr = _ida_allins.IA64_extr

IA64_f = _ida_allins.IA64_f

IA64_fabs = _ida_allins.IA64_fabs

IA64_fadd = _ida_allins.IA64_fadd

IA64_famax = _ida_allins.IA64_famax

IA64_famin = _ida_allins.IA64_famin

IA64_fand = _ida_allins.IA64_fand

IA64_fandcm = _ida_allins.IA64_fandcm

IA64_fault = _ida_allins.IA64_fault

IA64_fc = _ida_allins.IA64_fc

IA64_fchkf = _ida_allins.IA64_fchkf

IA64_fclass = _ida_allins.IA64_fclass

IA64_fclrf = _ida_allins.IA64_fclrf

IA64_fcmp = _ida_allins.IA64_fcmp

IA64_fcvt = _ida_allins.IA64_fcvt

IA64_fetchadd4 = _ida_allins.IA64_fetchadd4

IA64_fetchadd8 = _ida_allins.IA64_fetchadd8

IA64_few = _ida_allins.IA64_few

IA64_fill = _ida_allins.IA64_fill

IA64_flushrs = _ida_allins.IA64_flushrs

IA64_fma = _ida_allins.IA64_fma

IA64_fmax = _ida_allins.IA64_fmax

IA64_fmerge = _ida_allins.IA64_fmerge

IA64_fmin = _ida_allins.IA64_fmin

IA64_fmix = _ida_allins.IA64_fmix

IA64_fmpy = _ida_allins.IA64_fmpy

IA64_fms = _ida_allins.IA64_fms

IA64_fneg = _ida_allins.IA64_fneg

IA64_fnegabs = _ida_allins.IA64_fnegabs

IA64_fnma = _ida_allins.IA64_fnma

IA64_fnmpy = _ida_allins.IA64_fnmpy

IA64_fnorm = _ida_allins.IA64_fnorm

IA64_for = _ida_allins.IA64_for

IA64_fpabs = _ida_allins.IA64_fpabs

IA64_fpack = _ida_allins.IA64_fpack

IA64_fpamax = _ida_allins.IA64_fpamax

IA64_fpamin = _ida_allins.IA64_fpamin

IA64_fpcmp = _ida_allins.IA64_fpcmp

IA64_fpcvt = _ida_allins.IA64_fpcvt

IA64_fpma = _ida_allins.IA64_fpma

IA64_fpmax = _ida_allins.IA64_fpmax

IA64_fpmerge = _ida_allins.IA64_fpmerge

IA64_fpmin = _ida_allins.IA64_fpmin

IA64_fpmpy = _ida_allins.IA64_fpmpy

IA64_fpms = _ida_allins.IA64_fpms

IA64_fpneg = _ida_allins.IA64_fpneg

IA64_fpnegabs = _ida_allins.IA64_fpnegabs

IA64_fpnma = _ida_allins.IA64_fpnma

IA64_fpnmpy = _ida_allins.IA64_fpnmpy

IA64_fprcpa = _ida_allins.IA64_fprcpa

IA64_fprsqrta = _ida_allins.IA64_fprsqrta

IA64_frcpa = _ida_allins.IA64_frcpa

IA64_frsqrta = _ida_allins.IA64_frsqrta

IA64_fselect = _ida_allins.IA64_fselect

IA64_fsetc = _ida_allins.IA64_fsetc

IA64_fsub = _ida_allins.IA64_fsub

IA64_fswap = _ida_allins.IA64_fswap

IA64_fsxt = _ida_allins.IA64_fsxt

IA64_fwb = _ida_allins.IA64_fwb

IA64_fx = _ida_allins.IA64_fx

IA64_fxor = _ida_allins.IA64_fxor

IA64_fxu = _ida_allins.IA64_fxu

IA64_g = _ida_allins.IA64_g

IA64_ga = _ida_allins.IA64_ga

IA64_ge = _ida_allins.IA64_ge

IA64_getf = _ida_allins.IA64_getf

IA64_geu = _ida_allins.IA64_geu

IA64_gt = _ida_allins.IA64_gt

IA64_gtu = _ida_allins.IA64_gtu

IA64_h = _ida_allins.IA64_h

IA64_hu = _ida_allins.IA64_hu

IA64_i = _ida_allins.IA64_i

IA64_ia = _ida_allins.IA64_ia

IA64_imp = _ida_allins.IA64_imp

IA64_invala = _ida_allins.IA64_invala

IA64_itc = _ida_allins.IA64_itc

IA64_itr = _ida_allins.IA64_itr

IA64_l = _ida_allins.IA64_l

IA64_ld1 = _ida_allins.IA64_ld1

IA64_ld2 = _ida_allins.IA64_ld2

IA64_ld4 = _ida_allins.IA64_ld4

IA64_ld8 = _ida_allins.IA64_ld8

IA64_ldf = _ida_allins.IA64_ldf

IA64_ldf8 = _ida_allins.IA64_ldf8

IA64_ldfd = _ida_allins.IA64_ldfd

IA64_ldfe = _ida_allins.IA64_ldfe

IA64_ldfp8 = _ida_allins.IA64_ldfp8

IA64_ldfpd = _ida_allins.IA64_ldfpd

IA64_ldfps = _ida_allins.IA64_ldfps

IA64_ldfs = _ida_allins.IA64_ldfs

IA64_le = _ida_allins.IA64_le

IA64_leu = _ida_allins.IA64_leu

IA64_lfetch = _ida_allins.IA64_lfetch

IA64_loadrs = _ida_allins.IA64_loadrs

IA64_loop = _ida_allins.IA64_loop

IA64_lr = _ida_allins.IA64_lr

IA64_lt = _ida_allins.IA64_lt

IA64_ltu = _ida_allins.IA64_ltu

IA64_lu = _ida_allins.IA64_lu

IA64_m = _ida_allins.IA64_m

IA64_many = _ida_allins.IA64_many

IA64_mf = _ida_allins.IA64_mf

IA64_mix1 = _ida_allins.IA64_mix1

IA64_mix2 = _ida_allins.IA64_mix2

IA64_mix4 = _ida_allins.IA64_mix4

IA64_mov = _ida_allins.IA64_mov

IA64_movl = _ida_allins.IA64_movl

IA64_mux1 = _ida_allins.IA64_mux1

IA64_mux2 = _ida_allins.IA64_mux2

IA64_nc = _ida_allins.IA64_nc

IA64_ne = _ida_allins.IA64_ne

IA64_neq = _ida_allins.IA64_neq

IA64_nge = _ida_allins.IA64_nge

IA64_ngt = _ida_allins.IA64_ngt

IA64_nl = _ida_allins.IA64_nl

IA64_nle = _ida_allins.IA64_nle

IA64_nlt = _ida_allins.IA64_nlt

IA64_nm = _ida_allins.IA64_nm

IA64_nop = _ida_allins.IA64_nop

IA64_nr = _ida_allins.IA64_nr

IA64_ns = _ida_allins.IA64_ns

IA64_nt1 = _ida_allins.IA64_nt1

IA64_nt2 = _ida_allins.IA64_nt2

IA64_nta = _ida_allins.IA64_nta

IA64_nz = _ida_allins.IA64_nz

IA64_or = _ida_allins.IA64_or

IA64_orcm = _ida_allins.IA64_orcm

IA64_ord = _ida_allins.IA64_ord

IA64_pack2 = _ida_allins.IA64_pack2

IA64_pack4 = _ida_allins.IA64_pack4

IA64_padd1 = _ida_allins.IA64_padd1

IA64_padd2 = _ida_allins.IA64_padd2

IA64_padd4 = _ida_allins.IA64_padd4

IA64_pavg1 = _ida_allins.IA64_pavg1

IA64_pavg2 = _ida_allins.IA64_pavg2

IA64_pavgsub1 = _ida_allins.IA64_pavgsub1

IA64_pavgsub2 = _ida_allins.IA64_pavgsub2

IA64_pcmp1 = _ida_allins.IA64_pcmp1

IA64_pcmp2 = _ida_allins.IA64_pcmp2

IA64_pcmp4 = _ida_allins.IA64_pcmp4

IA64_pmax1 = _ida_allins.IA64_pmax1

IA64_pmax2 = _ida_allins.IA64_pmax2

IA64_pmin1 = _ida_allins.IA64_pmin1

IA64_pmin2 = _ida_allins.IA64_pmin2

IA64_pmpy2 = _ida_allins.IA64_pmpy2

IA64_pmpyshr2 = _ida_allins.IA64_pmpyshr2

IA64_popcnt = _ida_allins.IA64_popcnt

IA64_pr = _ida_allins.IA64_pr

IA64_probe = _ida_allins.IA64_probe

IA64_psad1 = _ida_allins.IA64_psad1

IA64_pshl2 = _ida_allins.IA64_pshl2

IA64_pshl4 = _ida_allins.IA64_pshl4

IA64_pshladd2 = _ida_allins.IA64_pshladd2

IA64_pshr2 = _ida_allins.IA64_pshr2

IA64_pshr4 = _ida_allins.IA64_pshr4

IA64_pshradd2 = _ida_allins.IA64_pshradd2

IA64_psub1 = _ida_allins.IA64_psub1

IA64_psub2 = _ida_allins.IA64_psub2

IA64_psub4 = _ida_allins.IA64_psub4

IA64_ptc = _ida_allins.IA64_ptc

IA64_ptr = _ida_allins.IA64_ptr

IA64_r = _ida_allins.IA64_r

IA64_raz = _ida_allins.IA64_raz

IA64_rel = _ida_allins.IA64_rel

IA64_ret = _ida_allins.IA64_ret

IA64_rfi = _ida_allins.IA64_rfi

IA64_rsm = _ida_allins.IA64_rsm

IA64_rum = _ida_allins.IA64_rum

IA64_rw = _ida_allins.IA64_rw

IA64_s = _ida_allins.IA64_s

IA64_s0 = _ida_allins.IA64_s0

IA64_s1 = _ida_allins.IA64_s1

IA64_s2 = _ida_allins.IA64_s2

IA64_s3 = _ida_allins.IA64_s3

IA64_sa = _ida_allins.IA64_sa

IA64_se = _ida_allins.IA64_se

IA64_setf = _ida_allins.IA64_setf

IA64_shl = _ida_allins.IA64_shl

IA64_shladd = _ida_allins.IA64_shladd

IA64_shladdp4 = _ida_allins.IA64_shladdp4

IA64_shr = _ida_allins.IA64_shr

IA64_shrp = _ida_allins.IA64_shrp

IA64_sig = _ida_allins.IA64_sig

IA64_spill = _ida_allins.IA64_spill

IA64_spnt = _ida_allins.IA64_spnt

IA64_sptk = _ida_allins.IA64_sptk

IA64_srlz = _ida_allins.IA64_srlz

IA64_ssm = _ida_allins.IA64_ssm

IA64_sss = _ida_allins.IA64_sss

IA64_st1 = _ida_allins.IA64_st1

IA64_st2 = _ida_allins.IA64_st2

IA64_st4 = _ida_allins.IA64_st4

IA64_st8 = _ida_allins.IA64_st8

IA64_stf = _ida_allins.IA64_stf

IA64_stf8 = _ida_allins.IA64_stf8

IA64_stfd = _ida_allins.IA64_stfd

IA64_stfe = _ida_allins.IA64_stfe

IA64_stfs = _ida_allins.IA64_stfs

IA64_sub = _ida_allins.IA64_sub

IA64_sum = _ida_allins.IA64_sum

IA64_sxt1 = _ida_allins.IA64_sxt1

IA64_sxt2 = _ida_allins.IA64_sxt2

IA64_sxt4 = _ida_allins.IA64_sxt4

IA64_sync = _ida_allins.IA64_sync

IA64_tak = _ida_allins.IA64_tak

IA64_tbit = _ida_allins.IA64_tbit

IA64_thash = _ida_allins.IA64_thash

IA64_tnat = _ida_allins.IA64_tnat

IA64_tpa = _ida_allins.IA64_tpa

IA64_trunc = _ida_allins.IA64_trunc

IA64_ttag = _ida_allins.IA64_ttag

IA64_u = _ida_allins.IA64_u

IA64_unc = _ida_allins.IA64_unc

IA64_unord = _ida_allins.IA64_unord

IA64_unpack1 = _ida_allins.IA64_unpack1

IA64_unpack2 = _ida_allins.IA64_unpack2

IA64_unpack4 = _ida_allins.IA64_unpack4

IA64_uss = _ida_allins.IA64_uss

IA64_uus = _ida_allins.IA64_uus

IA64_uuu = _ida_allins.IA64_uuu

IA64_w = _ida_allins.IA64_w

IA64_wexit = _ida_allins.IA64_wexit

IA64_wtop = _ida_allins.IA64_wtop

IA64_x = _ida_allins.IA64_x

IA64_xchg1 = _ida_allins.IA64_xchg1

IA64_xchg2 = _ida_allins.IA64_xchg2

IA64_xchg4 = _ida_allins.IA64_xchg4

IA64_xchg8 = _ida_allins.IA64_xchg8

IA64_xf = _ida_allins.IA64_xf

IA64_xma = _ida_allins.IA64_xma

IA64_xmpy = _ida_allins.IA64_xmpy

IA64_xor = _ida_allins.IA64_xor

IA64_xuf = _ida_allins.IA64_xuf

IA64_z = _ida_allins.IA64_z

IA64_zxt1 = _ida_allins.IA64_zxt1

IA64_zxt2 = _ida_allins.IA64_zxt2

IA64_zxt4 = _ida_allins.IA64_zxt4

IA64_last = _ida_allins.IA64_last

NET_null = _ida_allins.NET_null

NET_add = _ida_allins.NET_add

NET_add_ovf = _ida_allins.NET_add_ovf

NET_add_ovf_un = _ida_allins.NET_add_ovf_un

NET_and = _ida_allins.NET_and

NET_ann_arg = _ida_allins.NET_ann_arg

NET_ann_call = _ida_allins.NET_ann_call

NET_ann_catch = _ida_allins.NET_ann_catch

NET_ann_data = _ida_allins.NET_ann_data

NET_ann_data_s = _ida_allins.NET_ann_data_s

NET_ann_dead = _ida_allins.NET_ann_dead

NET_ann_def = _ida_allins.NET_ann_def

NET_ann_hoisted = _ida_allins.NET_ann_hoisted

NET_ann_hoisted_call = _ida_allins.NET_ann_hoisted_call

NET_ann_lab = _ida_allins.NET_ann_lab

NET_ann_live = _ida_allins.NET_ann_live

NET_ann_phi = _ida_allins.NET_ann_phi

NET_ann_ref = _ida_allins.NET_ann_ref

NET_ann_ref_s = _ida_allins.NET_ann_ref_s

NET_arglist = _ida_allins.NET_arglist

NET_beq = _ida_allins.NET_beq

NET_beq_s = _ida_allins.NET_beq_s

NET_bge = _ida_allins.NET_bge

NET_bge_s = _ida_allins.NET_bge_s

NET_bge_un = _ida_allins.NET_bge_un

NET_bge_un_s = _ida_allins.NET_bge_un_s

NET_bgt = _ida_allins.NET_bgt

NET_bgt_s = _ida_allins.NET_bgt_s

NET_bgt_un = _ida_allins.NET_bgt_un

NET_bgt_un_s = _ida_allins.NET_bgt_un_s

NET_ble = _ida_allins.NET_ble

NET_ble_s = _ida_allins.NET_ble_s

NET_ble_un = _ida_allins.NET_ble_un

NET_ble_un_s = _ida_allins.NET_ble_un_s

NET_blt = _ida_allins.NET_blt

NET_blt_s = _ida_allins.NET_blt_s

NET_blt_un = _ida_allins.NET_blt_un

NET_blt_un_s = _ida_allins.NET_blt_un_s

NET_bne_un = _ida_allins.NET_bne_un

NET_bne_un_s = _ida_allins.NET_bne_un_s

NET_box = _ida_allins.NET_box

NET_br = _ida_allins.NET_br

NET_br_s = _ida_allins.NET_br_s

NET_break = _ida_allins.NET_break

NET_brfalse = _ida_allins.NET_brfalse

NET_brfalse_s = _ida_allins.NET_brfalse_s

NET_brtrue = _ida_allins.NET_brtrue

NET_brtrue_s = _ida_allins.NET_brtrue_s

NET_call = _ida_allins.NET_call

NET_calli = _ida_allins.NET_calli

NET_callvirt = _ida_allins.NET_callvirt

NET_castclass = _ida_allins.NET_castclass

NET_ceq = _ida_allins.NET_ceq

NET_cgt = _ida_allins.NET_cgt

NET_cgt_un = _ida_allins.NET_cgt_un

NET_ckfinite = _ida_allins.NET_ckfinite

NET_clt = _ida_allins.NET_clt

NET_clt_un = _ida_allins.NET_clt_un

NET_conv_i = _ida_allins.NET_conv_i

NET_conv_i1 = _ida_allins.NET_conv_i1

NET_conv_i2 = _ida_allins.NET_conv_i2

NET_conv_i4 = _ida_allins.NET_conv_i4

NET_conv_i8 = _ida_allins.NET_conv_i8

NET_conv_ovf_i = _ida_allins.NET_conv_ovf_i

NET_conv_ovf_i1 = _ida_allins.NET_conv_ovf_i1

NET_conv_ovf_i1_un = _ida_allins.NET_conv_ovf_i1_un

NET_conv_ovf_i2 = _ida_allins.NET_conv_ovf_i2

NET_conv_ovf_i2_un = _ida_allins.NET_conv_ovf_i2_un

NET_conv_ovf_i4 = _ida_allins.NET_conv_ovf_i4

NET_conv_ovf_i4_un = _ida_allins.NET_conv_ovf_i4_un

NET_conv_ovf_i8 = _ida_allins.NET_conv_ovf_i8

NET_conv_ovf_i8_un = _ida_allins.NET_conv_ovf_i8_un

NET_conv_ovf_i_un = _ida_allins.NET_conv_ovf_i_un

NET_conv_ovf_u = _ida_allins.NET_conv_ovf_u

NET_conv_ovf_u1 = _ida_allins.NET_conv_ovf_u1

NET_conv_ovf_u1_un = _ida_allins.NET_conv_ovf_u1_un

NET_conv_ovf_u2 = _ida_allins.NET_conv_ovf_u2

NET_conv_ovf_u2_un = _ida_allins.NET_conv_ovf_u2_un

NET_conv_ovf_u4 = _ida_allins.NET_conv_ovf_u4

NET_conv_ovf_u4_un = _ida_allins.NET_conv_ovf_u4_un

NET_conv_ovf_u8 = _ida_allins.NET_conv_ovf_u8

NET_conv_ovf_u8_un = _ida_allins.NET_conv_ovf_u8_un

NET_conv_ovf_u_un = _ida_allins.NET_conv_ovf_u_un

NET_conv_r4 = _ida_allins.NET_conv_r4

NET_conv_r8 = _ida_allins.NET_conv_r8

NET_conv_r_un = _ida_allins.NET_conv_r_un

NET_conv_u = _ida_allins.NET_conv_u

NET_conv_u1 = _ida_allins.NET_conv_u1

NET_conv_u2 = _ida_allins.NET_conv_u2

NET_conv_u4 = _ida_allins.NET_conv_u4

NET_conv_u8 = _ida_allins.NET_conv_u8

NET_cpblk = _ida_allins.NET_cpblk

NET_cpobj = _ida_allins.NET_cpobj

NET_div = _ida_allins.NET_div

NET_div_un = _ida_allins.NET_div_un

NET_dup = _ida_allins.NET_dup

NET_endfilter = _ida_allins.NET_endfilter

NET_endfinally = _ida_allins.NET_endfinally

NET_initblk = _ida_allins.NET_initblk

NET_initobj = _ida_allins.NET_initobj

NET_isinst = _ida_allins.NET_isinst

NET_jmp = _ida_allins.NET_jmp

NET_ldarg = _ida_allins.NET_ldarg

NET_ldarg_0 = _ida_allins.NET_ldarg_0

NET_ldarg_1 = _ida_allins.NET_ldarg_1

NET_ldarg_2 = _ida_allins.NET_ldarg_2

NET_ldarg_3 = _ida_allins.NET_ldarg_3

NET_ldarg_s = _ida_allins.NET_ldarg_s

NET_ldarga = _ida_allins.NET_ldarga

NET_ldarga_s = _ida_allins.NET_ldarga_s

NET_ldc_i4 = _ida_allins.NET_ldc_i4

NET_ldc_i4_0 = _ida_allins.NET_ldc_i4_0

NET_ldc_i4_1 = _ida_allins.NET_ldc_i4_1

NET_ldc_i4_2 = _ida_allins.NET_ldc_i4_2

NET_ldc_i4_3 = _ida_allins.NET_ldc_i4_3

NET_ldc_i4_4 = _ida_allins.NET_ldc_i4_4

NET_ldc_i4_5 = _ida_allins.NET_ldc_i4_5

NET_ldc_i4_6 = _ida_allins.NET_ldc_i4_6

NET_ldc_i4_7 = _ida_allins.NET_ldc_i4_7

NET_ldc_i4_8 = _ida_allins.NET_ldc_i4_8

NET_ldc_i4_m1 = _ida_allins.NET_ldc_i4_m1

NET_ldc_i4_s = _ida_allins.NET_ldc_i4_s

NET_ldc_i8 = _ida_allins.NET_ldc_i8

NET_ldc_r4 = _ida_allins.NET_ldc_r4

NET_ldc_r8 = _ida_allins.NET_ldc_r8

NET_ldelem_i = _ida_allins.NET_ldelem_i

NET_ldelem_i1 = _ida_allins.NET_ldelem_i1

NET_ldelem_i2 = _ida_allins.NET_ldelem_i2

NET_ldelem_i4 = _ida_allins.NET_ldelem_i4

NET_ldelem_i8 = _ida_allins.NET_ldelem_i8

NET_ldelem_r4 = _ida_allins.NET_ldelem_r4

NET_ldelem_r8 = _ida_allins.NET_ldelem_r8

NET_ldelem_ref = _ida_allins.NET_ldelem_ref

NET_ldelem_u1 = _ida_allins.NET_ldelem_u1

NET_ldelem_u2 = _ida_allins.NET_ldelem_u2

NET_ldelem_u4 = _ida_allins.NET_ldelem_u4

NET_ldelema = _ida_allins.NET_ldelema

NET_ldfld = _ida_allins.NET_ldfld

NET_ldflda = _ida_allins.NET_ldflda

NET_ldftn = _ida_allins.NET_ldftn

NET_ldind_i = _ida_allins.NET_ldind_i

NET_ldind_i1 = _ida_allins.NET_ldind_i1

NET_ldind_i2 = _ida_allins.NET_ldind_i2

NET_ldind_i4 = _ida_allins.NET_ldind_i4

NET_ldind_i8 = _ida_allins.NET_ldind_i8

NET_ldind_r4 = _ida_allins.NET_ldind_r4

NET_ldind_r8 = _ida_allins.NET_ldind_r8

NET_ldind_ref = _ida_allins.NET_ldind_ref

NET_ldind_u1 = _ida_allins.NET_ldind_u1

NET_ldind_u2 = _ida_allins.NET_ldind_u2

NET_ldind_u4 = _ida_allins.NET_ldind_u4

NET_ldlen = _ida_allins.NET_ldlen

NET_ldloc = _ida_allins.NET_ldloc

NET_ldloc_0 = _ida_allins.NET_ldloc_0

NET_ldloc_1 = _ida_allins.NET_ldloc_1

NET_ldloc_2 = _ida_allins.NET_ldloc_2

NET_ldloc_3 = _ida_allins.NET_ldloc_3

NET_ldloc_s = _ida_allins.NET_ldloc_s

NET_ldloca = _ida_allins.NET_ldloca

NET_ldloca_s = _ida_allins.NET_ldloca_s

NET_ldnull = _ida_allins.NET_ldnull

NET_ldobj = _ida_allins.NET_ldobj

NET_ldsfld = _ida_allins.NET_ldsfld

NET_ldsflda = _ida_allins.NET_ldsflda

NET_ldstr = _ida_allins.NET_ldstr

NET_ldtoken = _ida_allins.NET_ldtoken

NET_ldvirtftn = _ida_allins.NET_ldvirtftn

NET_leave = _ida_allins.NET_leave

NET_leave_s = _ida_allins.NET_leave_s

NET_localloc = _ida_allins.NET_localloc

NET_mkrefany = _ida_allins.NET_mkrefany

NET_mul = _ida_allins.NET_mul

NET_mul_ovf = _ida_allins.NET_mul_ovf

NET_mul_ovf_un = _ida_allins.NET_mul_ovf_un

NET_neg = _ida_allins.NET_neg

NET_newarr = _ida_allins.NET_newarr

NET_newobj = _ida_allins.NET_newobj

NET_nop = _ida_allins.NET_nop

NET_not = _ida_allins.NET_not

NET_or = _ida_allins.NET_or

NET_pop = _ida_allins.NET_pop

NET_refanytype = _ida_allins.NET_refanytype

NET_refanyval = _ida_allins.NET_refanyval

NET_rem = _ida_allins.NET_rem

NET_rem_un = _ida_allins.NET_rem_un

NET_ret = _ida_allins.NET_ret

NET_rethrow = _ida_allins.NET_rethrow

NET_shl = _ida_allins.NET_shl

NET_shr = _ida_allins.NET_shr

NET_shr_un = _ida_allins.NET_shr_un

NET_sizeof = _ida_allins.NET_sizeof

NET_starg = _ida_allins.NET_starg

NET_starg_s = _ida_allins.NET_starg_s

NET_stelem_i = _ida_allins.NET_stelem_i

NET_stelem_i1 = _ida_allins.NET_stelem_i1

NET_stelem_i2 = _ida_allins.NET_stelem_i2

NET_stelem_i4 = _ida_allins.NET_stelem_i4

NET_stelem_i8 = _ida_allins.NET_stelem_i8

NET_stelem_r4 = _ida_allins.NET_stelem_r4

NET_stelem_r8 = _ida_allins.NET_stelem_r8

NET_stelem_ref = _ida_allins.NET_stelem_ref

NET_stfld = _ida_allins.NET_stfld

NET_stind_i = _ida_allins.NET_stind_i

NET_stind_i1 = _ida_allins.NET_stind_i1

NET_stind_i2 = _ida_allins.NET_stind_i2

NET_stind_i4 = _ida_allins.NET_stind_i4

NET_stind_i8 = _ida_allins.NET_stind_i8

NET_stind_r4 = _ida_allins.NET_stind_r4

NET_stind_r8 = _ida_allins.NET_stind_r8

NET_stind_ref = _ida_allins.NET_stind_ref

NET_stloc = _ida_allins.NET_stloc

NET_stloc_0 = _ida_allins.NET_stloc_0

NET_stloc_1 = _ida_allins.NET_stloc_1

NET_stloc_2 = _ida_allins.NET_stloc_2

NET_stloc_3 = _ida_allins.NET_stloc_3

NET_stloc_s = _ida_allins.NET_stloc_s

NET_stobj = _ida_allins.NET_stobj

NET_stsfld = _ida_allins.NET_stsfld

NET_sub = _ida_allins.NET_sub

NET_sub_ovf = _ida_allins.NET_sub_ovf

NET_sub_ovf_un = _ida_allins.NET_sub_ovf_un

NET_switch = _ida_allins.NET_switch

NET_tail_ = _ida_allins.NET_tail_

NET_throw = _ida_allins.NET_throw

NET_unaligned_ = _ida_allins.NET_unaligned_

NET_unbox = _ida_allins.NET_unbox

NET_volatile_ = _ida_allins.NET_volatile_

NET_xor = _ida_allins.NET_xor

NET_ldelem = _ida_allins.NET_ldelem

NET_stelem = _ida_allins.NET_stelem

NET_unbox_any = _ida_allins.NET_unbox_any

NET_constrained_ = _ida_allins.NET_constrained_

NET_no_ = _ida_allins.NET_no_

NET_readonly_ = _ida_allins.NET_readonly_

NET_last = _ida_allins.NET_last

MC12_null = _ida_allins.MC12_null

MC12_aba = _ida_allins.MC12_aba

MC12_abx = _ida_allins.MC12_abx

MC12_aby = _ida_allins.MC12_aby

MC12_adca = _ida_allins.MC12_adca

MC12_adcb = _ida_allins.MC12_adcb

MC12_adda = _ida_allins.MC12_adda

MC12_addb = _ida_allins.MC12_addb

MC12_addd = _ida_allins.MC12_addd

MC12_anda = _ida_allins.MC12_anda

MC12_andb = _ida_allins.MC12_andb

MC12_andcc = _ida_allins.MC12_andcc

MC12_asl = _ida_allins.MC12_asl

MC12_asla = _ida_allins.MC12_asla

MC12_aslb = _ida_allins.MC12_aslb

MC12_asld = _ida_allins.MC12_asld

MC12_asr = _ida_allins.MC12_asr

MC12_asra = _ida_allins.MC12_asra

MC12_asrb = _ida_allins.MC12_asrb

MC12_bcc = _ida_allins.MC12_bcc

MC12_bclr = _ida_allins.MC12_bclr

MC12_bcs = _ida_allins.MC12_bcs

MC12_beq = _ida_allins.MC12_beq

MC12_bge = _ida_allins.MC12_bge

MC12_bgnd = _ida_allins.MC12_bgnd

MC12_bgt = _ida_allins.MC12_bgt

MC12_bhi = _ida_allins.MC12_bhi

MC12_bhs = _ida_allins.MC12_bhs

MC12_bita = _ida_allins.MC12_bita

MC12_bitb = _ida_allins.MC12_bitb

MC12_ble = _ida_allins.MC12_ble

MC12_blo = _ida_allins.MC12_blo

MC12_bls = _ida_allins.MC12_bls

MC12_blt = _ida_allins.MC12_blt

MC12_bmi = _ida_allins.MC12_bmi

MC12_bne = _ida_allins.MC12_bne

MC12_bpl = _ida_allins.MC12_bpl

MC12_bra = _ida_allins.MC12_bra

MC12_brclr = _ida_allins.MC12_brclr

MC12_brn = _ida_allins.MC12_brn

MC12_brset = _ida_allins.MC12_brset

MC12_bset = _ida_allins.MC12_bset

MC12_bsr = _ida_allins.MC12_bsr

MC12_bvc = _ida_allins.MC12_bvc

MC12_bvs = _ida_allins.MC12_bvs

MC12_call = _ida_allins.MC12_call

MC12_cba = _ida_allins.MC12_cba

MC12_clc = _ida_allins.MC12_clc

MC12_cli = _ida_allins.MC12_cli

MC12_clr = _ida_allins.MC12_clr

MC12_clra = _ida_allins.MC12_clra

MC12_clrb = _ida_allins.MC12_clrb

MC12_clv = _ida_allins.MC12_clv

MC12_cmpa = _ida_allins.MC12_cmpa

MC12_cmpb = _ida_allins.MC12_cmpb

MC12_com = _ida_allins.MC12_com

MC12_coma = _ida_allins.MC12_coma

MC12_comb = _ida_allins.MC12_comb

MC12_cpd = _ida_allins.MC12_cpd

MC12_cps = _ida_allins.MC12_cps

MC12_cpx = _ida_allins.MC12_cpx

MC12_cpy = _ida_allins.MC12_cpy

MC12_daa = _ida_allins.MC12_daa

MC12_dbeq = _ida_allins.MC12_dbeq

MC12_dbne = _ida_allins.MC12_dbne

MC12_dec = _ida_allins.MC12_dec

MC12_deca = _ida_allins.MC12_deca

MC12_decb = _ida_allins.MC12_decb

MC12_des = _ida_allins.MC12_des

MC12_dex = _ida_allins.MC12_dex

MC12_dey = _ida_allins.MC12_dey

MC12_ediv = _ida_allins.MC12_ediv

MC12_edivs = _ida_allins.MC12_edivs

MC12_emacs = _ida_allins.MC12_emacs

MC12_emaxd = _ida_allins.MC12_emaxd

MC12_emaxm = _ida_allins.MC12_emaxm

MC12_emind = _ida_allins.MC12_emind

MC12_eminm = _ida_allins.MC12_eminm

MC12_emul = _ida_allins.MC12_emul

MC12_emuls = _ida_allins.MC12_emuls

MC12_eora = _ida_allins.MC12_eora

MC12_eorb = _ida_allins.MC12_eorb

MC12_etbl = _ida_allins.MC12_etbl

MC12_exg = _ida_allins.MC12_exg

MC12_fdiv = _ida_allins.MC12_fdiv

MC12_ibeq = _ida_allins.MC12_ibeq

MC12_ibne = _ida_allins.MC12_ibne

MC12_idiv = _ida_allins.MC12_idiv

MC12_idivs = _ida_allins.MC12_idivs

MC12_inc = _ida_allins.MC12_inc

MC12_inca = _ida_allins.MC12_inca

MC12_incb = _ida_allins.MC12_incb

MC12_ins = _ida_allins.MC12_ins

MC12_inx = _ida_allins.MC12_inx

MC12_iny = _ida_allins.MC12_iny

MC12_jmp = _ida_allins.MC12_jmp

MC12_jsr = _ida_allins.MC12_jsr

MC12_lbcc = _ida_allins.MC12_lbcc

MC12_lbcs = _ida_allins.MC12_lbcs

MC12_lbeq = _ida_allins.MC12_lbeq

MC12_lbge = _ida_allins.MC12_lbge

MC12_lbgt = _ida_allins.MC12_lbgt

MC12_lbhi = _ida_allins.MC12_lbhi

MC12_lbhs = _ida_allins.MC12_lbhs

MC12_lble = _ida_allins.MC12_lble

MC12_lblo = _ida_allins.MC12_lblo

MC12_lbls = _ida_allins.MC12_lbls

MC12_lblt = _ida_allins.MC12_lblt

MC12_lbmi = _ida_allins.MC12_lbmi

MC12_lbne = _ida_allins.MC12_lbne

MC12_lbpl = _ida_allins.MC12_lbpl

MC12_lbra = _ida_allins.MC12_lbra

MC12_lbrn = _ida_allins.MC12_lbrn

MC12_lbvc = _ida_allins.MC12_lbvc

MC12_lbvs = _ida_allins.MC12_lbvs

MC12_ldaa = _ida_allins.MC12_ldaa

MC12_ldab = _ida_allins.MC12_ldab

MC12_ldd = _ida_allins.MC12_ldd

MC12_lds = _ida_allins.MC12_lds

MC12_ldx = _ida_allins.MC12_ldx

MC12_ldy = _ida_allins.MC12_ldy

MC12_leas = _ida_allins.MC12_leas

MC12_leax = _ida_allins.MC12_leax

MC12_leay = _ida_allins.MC12_leay

MC12_lsl = _ida_allins.MC12_lsl

MC12_lsla = _ida_allins.MC12_lsla

MC12_lslb = _ida_allins.MC12_lslb

MC12_lsld = _ida_allins.MC12_lsld

MC12_lsr = _ida_allins.MC12_lsr

MC12_lsra = _ida_allins.MC12_lsra

MC12_lsrb = _ida_allins.MC12_lsrb

MC12_lsrd = _ida_allins.MC12_lsrd

MC12_maxa = _ida_allins.MC12_maxa

MC12_maxm = _ida_allins.MC12_maxm

MC12_mem = _ida_allins.MC12_mem

MC12_mina = _ida_allins.MC12_mina

MC12_minm = _ida_allins.MC12_minm

MC12_movb = _ida_allins.MC12_movb

MC12_movw = _ida_allins.MC12_movw

MC12_mul = _ida_allins.MC12_mul

MC12_neg = _ida_allins.MC12_neg

MC12_nega = _ida_allins.MC12_nega

MC12_negb = _ida_allins.MC12_negb

MC12_nop = _ida_allins.MC12_nop

MC12_oraa = _ida_allins.MC12_oraa

MC12_orab = _ida_allins.MC12_orab

MC12_orcc = _ida_allins.MC12_orcc

MC12_psha = _ida_allins.MC12_psha

MC12_pshb = _ida_allins.MC12_pshb

MC12_pshc = _ida_allins.MC12_pshc

MC12_pshd = _ida_allins.MC12_pshd

MC12_pshx = _ida_allins.MC12_pshx

MC12_pshy = _ida_allins.MC12_pshy

MC12_pula = _ida_allins.MC12_pula

MC12_pulb = _ida_allins.MC12_pulb

MC12_pulc = _ida_allins.MC12_pulc

MC12_puld = _ida_allins.MC12_puld

MC12_pulx = _ida_allins.MC12_pulx

MC12_puly = _ida_allins.MC12_puly

MC12_rev = _ida_allins.MC12_rev

MC12_revw = _ida_allins.MC12_revw

MC12_rol = _ida_allins.MC12_rol

MC12_rola = _ida_allins.MC12_rola

MC12_rolb = _ida_allins.MC12_rolb

MC12_ror = _ida_allins.MC12_ror

MC12_rora = _ida_allins.MC12_rora

MC12_rorb = _ida_allins.MC12_rorb

MC12_rtc = _ida_allins.MC12_rtc

MC12_rti = _ida_allins.MC12_rti

MC12_rts = _ida_allins.MC12_rts

MC12_sba = _ida_allins.MC12_sba

MC12_sbca = _ida_allins.MC12_sbca

MC12_sbcb = _ida_allins.MC12_sbcb

MC12_sec = _ida_allins.MC12_sec

MC12_sei = _ida_allins.MC12_sei

MC12_sev = _ida_allins.MC12_sev

MC12_sex = _ida_allins.MC12_sex

MC12_staa = _ida_allins.MC12_staa

MC12_stab = _ida_allins.MC12_stab

MC12_std = _ida_allins.MC12_std

MC12_stop = _ida_allins.MC12_stop

MC12_sts = _ida_allins.MC12_sts

MC12_stx = _ida_allins.MC12_stx

MC12_sty = _ida_allins.MC12_sty

MC12_suba = _ida_allins.MC12_suba

MC12_subb = _ida_allins.MC12_subb

MC12_subd = _ida_allins.MC12_subd

MC12_swi = _ida_allins.MC12_swi

MC12_tab = _ida_allins.MC12_tab

MC12_tap = _ida_allins.MC12_tap

MC12_tba = _ida_allins.MC12_tba

MC12_tbeq = _ida_allins.MC12_tbeq

MC12_tbl = _ida_allins.MC12_tbl

MC12_tbne = _ida_allins.MC12_tbne

MC12_tfr = _ida_allins.MC12_tfr

MC12_tpa = _ida_allins.MC12_tpa

MC12_trap = _ida_allins.MC12_trap

MC12_tst = _ida_allins.MC12_tst

MC12_tsta = _ida_allins.MC12_tsta

MC12_tstb = _ida_allins.MC12_tstb

MC12_tsx = _ida_allins.MC12_tsx

MC12_tsy = _ida_allins.MC12_tsy

MC12_txs = _ida_allins.MC12_txs

MC12_tys = _ida_allins.MC12_tys

MC12_wai = _ida_allins.MC12_wai

MC12_wav = _ida_allins.MC12_wav

MC12_wavr = _ida_allins.MC12_wavr

MC12_xgdx = _ida_allins.MC12_xgdx

MC12_xgdy = _ida_allins.MC12_xgdy

MC12_skip1 = _ida_allins.MC12_skip1

MC12_skip2 = _ida_allins.MC12_skip2

MC12X_addx = _ida_allins.MC12X_addx

MC12X_addy = _ida_allins.MC12X_addy

MC12X_aded = _ida_allins.MC12X_aded

MC12X_adex = _ida_allins.MC12X_adex

MC12X_adey = _ida_allins.MC12X_adey

MC12X_andx = _ida_allins.MC12X_andx

MC12X_andy = _ida_allins.MC12X_andy

MC12X_aslw = _ida_allins.MC12X_aslw

MC12X_aslx = _ida_allins.MC12X_aslx

MC12X_asly = _ida_allins.MC12X_asly

MC12X_asrw = _ida_allins.MC12X_asrw

MC12X_asrx = _ida_allins.MC12X_asrx

MC12X_asry = _ida_allins.MC12X_asry

MC12X_bitx = _ida_allins.MC12X_bitx

MC12X_bity = _ida_allins.MC12X_bity

MC12X_btas = _ida_allins.MC12X_btas

MC12X_clrw = _ida_allins.MC12X_clrw

MC12X_clrx = _ida_allins.MC12X_clrx

MC12X_clry = _ida_allins.MC12X_clry

MC12X_comw = _ida_allins.MC12X_comw

MC12X_comx = _ida_allins.MC12X_comx

MC12X_comy = _ida_allins.MC12X_comy

MC12X_cped = _ida_allins.MC12X_cped

MC12X_cpes = _ida_allins.MC12X_cpes

MC12X_cpex = _ida_allins.MC12X_cpex

MC12X_cpey = _ida_allins.MC12X_cpey

MC12X_decw = _ida_allins.MC12X_decw

MC12X_decx = _ida_allins.MC12X_decx

MC12X_decy = _ida_allins.MC12X_decy

MC12X_eorx = _ida_allins.MC12X_eorx

MC12X_eory = _ida_allins.MC12X_eory

MC12X_gldaa = _ida_allins.MC12X_gldaa

MC12X_gldab = _ida_allins.MC12X_gldab

MC12X_gldd = _ida_allins.MC12X_gldd

MC12X_glds = _ida_allins.MC12X_glds

MC12X_gldx = _ida_allins.MC12X_gldx

MC12X_gldy = _ida_allins.MC12X_gldy

MC12X_gstaa = _ida_allins.MC12X_gstaa

MC12X_gstab = _ida_allins.MC12X_gstab

MC12X_gstd = _ida_allins.MC12X_gstd

MC12X_gsts = _ida_allins.MC12X_gsts

MC12X_gstx = _ida_allins.MC12X_gstx

MC12X_gsty = _ida_allins.MC12X_gsty

MC12X_incw = _ida_allins.MC12X_incw

MC12X_incx = _ida_allins.MC12X_incx

MC12X_incy = _ida_allins.MC12X_incy

MC12X_lsrw = _ida_allins.MC12X_lsrw

MC12X_lsrx = _ida_allins.MC12X_lsrx

MC12X_lsry = _ida_allins.MC12X_lsry

MC12X_negw = _ida_allins.MC12X_negw

MC12X_negx = _ida_allins.MC12X_negx

MC12X_negy = _ida_allins.MC12X_negy

MC12X_orx = _ida_allins.MC12X_orx

MC12X_ory = _ida_allins.MC12X_ory

MC12X_pshcw = _ida_allins.MC12X_pshcw

MC12X_pulcw = _ida_allins.MC12X_pulcw

MC12X_rolw = _ida_allins.MC12X_rolw

MC12X_rolx = _ida_allins.MC12X_rolx

MC12X_roly = _ida_allins.MC12X_roly

MC12X_rorw = _ida_allins.MC12X_rorw

MC12X_rorx = _ida_allins.MC12X_rorx

MC12X_rory = _ida_allins.MC12X_rory

MC12X_sbed = _ida_allins.MC12X_sbed

MC12X_sbex = _ida_allins.MC12X_sbex

MC12X_sbey = _ida_allins.MC12X_sbey

MC12X_subx = _ida_allins.MC12X_subx

MC12X_suby = _ida_allins.MC12X_suby

MC12X_tstw = _ida_allins.MC12X_tstw

MC12X_tstx = _ida_allins.MC12X_tstx

MC12X_tsty = _ida_allins.MC12X_tsty

MC12X_sys = _ida_allins.MC12X_sys

MC12XGATE_adc = _ida_allins.MC12XGATE_adc

MC12XGATE_add = _ida_allins.MC12XGATE_add

MC12XGATE_addh = _ida_allins.MC12XGATE_addh

MC12XGATE_addl = _ida_allins.MC12XGATE_addl

MC12XGATE_and = _ida_allins.MC12XGATE_and

MC12XGATE_andh = _ida_allins.MC12XGATE_andh

MC12XGATE_andl = _ida_allins.MC12XGATE_andl

MC12XGATE_asr = _ida_allins.MC12XGATE_asr

MC12XGATE_bcc = _ida_allins.MC12XGATE_bcc

MC12XGATE_bcs = _ida_allins.MC12XGATE_bcs

MC12XGATE_beq = _ida_allins.MC12XGATE_beq

MC12XGATE_bfext = _ida_allins.MC12XGATE_bfext

MC12XGATE_bffo = _ida_allins.MC12XGATE_bffo

MC12XGATE_bfins = _ida_allins.MC12XGATE_bfins

MC12XGATE_bfinsi = _ida_allins.MC12XGATE_bfinsi

MC12XGATE_bfinsx = _ida_allins.MC12XGATE_bfinsx

MC12XGATE_bge = _ida_allins.MC12XGATE_bge

MC12XGATE_bgt = _ida_allins.MC12XGATE_bgt

MC12XGATE_bhi = _ida_allins.MC12XGATE_bhi

MC12XGATE_bhs = _ida_allins.MC12XGATE_bhs

MC12XGATE_bith = _ida_allins.MC12XGATE_bith

MC12XGATE_bitl = _ida_allins.MC12XGATE_bitl

MC12XGATE_ble = _ida_allins.MC12XGATE_ble

MC12XGATE_blo = _ida_allins.MC12XGATE_blo

MC12XGATE_bls = _ida_allins.MC12XGATE_bls

MC12XGATE_blt = _ida_allins.MC12XGATE_blt

MC12XGATE_bmi = _ida_allins.MC12XGATE_bmi

MC12XGATE_bne = _ida_allins.MC12XGATE_bne

MC12XGATE_bpl = _ida_allins.MC12XGATE_bpl

MC12XGATE_bra = _ida_allins.MC12XGATE_bra

MC12XGATE_brk = _ida_allins.MC12XGATE_brk

MC12XGATE_bvc = _ida_allins.MC12XGATE_bvc

MC12XGATE_bvs = _ida_allins.MC12XGATE_bvs

MC12XGATE_cmp = _ida_allins.MC12XGATE_cmp

MC12XGATE_cmpl = _ida_allins.MC12XGATE_cmpl

MC12XGATE_com = _ida_allins.MC12XGATE_com

MC12XGATE_cpc = _ida_allins.MC12XGATE_cpc

MC12XGATE_cpch = _ida_allins.MC12XGATE_cpch

MC12XGATE_csem = _ida_allins.MC12XGATE_csem

MC12XGATE_csl = _ida_allins.MC12XGATE_csl

MC12XGATE_csr = _ida_allins.MC12XGATE_csr

MC12XGATE_jal = _ida_allins.MC12XGATE_jal

MC12XGATE_ldb = _ida_allins.MC12XGATE_ldb

MC12XGATE_ldh = _ida_allins.MC12XGATE_ldh

MC12XGATE_ldl = _ida_allins.MC12XGATE_ldl

MC12XGATE_ldw = _ida_allins.MC12XGATE_ldw

MC12XGATE_lsl = _ida_allins.MC12XGATE_lsl

MC12XGATE_lsr = _ida_allins.MC12XGATE_lsr

MC12XGATE_mov = _ida_allins.MC12XGATE_mov

MC12XGATE_neg = _ida_allins.MC12XGATE_neg

MC12XGATE_nop = _ida_allins.MC12XGATE_nop

MC12XGATE_or = _ida_allins.MC12XGATE_or

MC12XGATE_orh = _ida_allins.MC12XGATE_orh

MC12XGATE_orl = _ida_allins.MC12XGATE_orl

MC12XGATE_par = _ida_allins.MC12XGATE_par

MC12XGATE_rol = _ida_allins.MC12XGATE_rol

MC12XGATE_ror = _ida_allins.MC12XGATE_ror

MC12XGATE_rts = _ida_allins.MC12XGATE_rts

MC12XGATE_sbc = _ida_allins.MC12XGATE_sbc

MC12XGATE_sex = _ida_allins.MC12XGATE_sex

MC12XGATE_sif = _ida_allins.MC12XGATE_sif

MC12XGATE_ssem = _ida_allins.MC12XGATE_ssem

MC12XGATE_stb = _ida_allins.MC12XGATE_stb

MC12XGATE_stw = _ida_allins.MC12XGATE_stw

MC12XGATE_sub = _ida_allins.MC12XGATE_sub

MC12XGATE_subh = _ida_allins.MC12XGATE_subh

MC12XGATE_subl = _ida_allins.MC12XGATE_subl

MC12XGATE_tfr = _ida_allins.MC12XGATE_tfr

MC12XGATE_tst = _ida_allins.MC12XGATE_tst

MC12XGATE_xnor = _ida_allins.MC12XGATE_xnor

MC12XGATE_xnorh = _ida_allins.MC12XGATE_xnorh

MC12XGATE_xnorl = _ida_allins.MC12XGATE_xnorl

MC12XGATE_add16 = _ida_allins.MC12XGATE_add16

MC12XGATE_and16 = _ida_allins.MC12XGATE_and16

MC12XGATE_cmp16 = _ida_allins.MC12XGATE_cmp16

MC12XGATE_ldw16 = _ida_allins.MC12XGATE_ldw16

MC12XGATE_or16 = _ida_allins.MC12XGATE_or16

MC12XGATE_sub16 = _ida_allins.MC12XGATE_sub16

MC12XGATE_xnor16 = _ida_allins.MC12XGATE_xnor16

MC12_last = _ida_allins.MC12_last

MC6816_null = _ida_allins.MC6816_null

MC6816_ldaa = _ida_allins.MC6816_ldaa

MC6816_ldab = _ida_allins.MC6816_ldab

MC6816_ldd = _ida_allins.MC6816_ldd

MC6816_lde = _ida_allins.MC6816_lde

MC6816_lded = _ida_allins.MC6816_lded

MC6816_movb = _ida_allins.MC6816_movb

MC6816_movw = _ida_allins.MC6816_movw

MC6816_staa = _ida_allins.MC6816_staa

MC6816_stab = _ida_allins.MC6816_stab

MC6816_std = _ida_allins.MC6816_std

MC6816_ste = _ida_allins.MC6816_ste

MC6816_sted = _ida_allins.MC6816_sted

MC6816_tab = _ida_allins.MC6816_tab

MC6816_tba = _ida_allins.MC6816_tba

MC6816_tde = _ida_allins.MC6816_tde

MC6816_ted = _ida_allins.MC6816_ted

MC6816_xgab = _ida_allins.MC6816_xgab

MC6816_xgde = _ida_allins.MC6816_xgde

MC6816_aba = _ida_allins.MC6816_aba

MC6816_adca = _ida_allins.MC6816_adca

MC6816_adcb = _ida_allins.MC6816_adcb

MC6816_adcd = _ida_allins.MC6816_adcd

MC6816_adce = _ida_allins.MC6816_adce

MC6816_adda = _ida_allins.MC6816_adda

MC6816_addb = _ida_allins.MC6816_addb

MC6816_addd = _ida_allins.MC6816_addd

MC6816_adde = _ida_allins.MC6816_adde

MC6816_ade = _ida_allins.MC6816_ade

MC6816_sba = _ida_allins.MC6816_sba

MC6816_sbca = _ida_allins.MC6816_sbca

MC6816_sbcb = _ida_allins.MC6816_sbcb

MC6816_sbcd = _ida_allins.MC6816_sbcd

MC6816_sbce = _ida_allins.MC6816_sbce

MC6816_sde = _ida_allins.MC6816_sde

MC6816_suba = _ida_allins.MC6816_suba

MC6816_subb = _ida_allins.MC6816_subb

MC6816_subd = _ida_allins.MC6816_subd

MC6816_sube = _ida_allins.MC6816_sube

MC6816_daa = _ida_allins.MC6816_daa

MC6816_sxt = _ida_allins.MC6816_sxt

MC6816_cba = _ida_allins.MC6816_cba

MC6816_cmpa = _ida_allins.MC6816_cmpa

MC6816_cmpb = _ida_allins.MC6816_cmpb

MC6816_cpd = _ida_allins.MC6816_cpd

MC6816_cpe = _ida_allins.MC6816_cpe

MC6816_tst = _ida_allins.MC6816_tst

MC6816_tsta = _ida_allins.MC6816_tsta

MC6816_tstb = _ida_allins.MC6816_tstb

MC6816_tstd = _ida_allins.MC6816_tstd

MC6816_tste = _ida_allins.MC6816_tste

MC6816_tstw = _ida_allins.MC6816_tstw

MC6816_ediv = _ida_allins.MC6816_ediv

MC6816_edivs = _ida_allins.MC6816_edivs

MC6816_emul = _ida_allins.MC6816_emul

MC6816_emuls = _ida_allins.MC6816_emuls

MC6816_fdiv = _ida_allins.MC6816_fdiv

MC6816_fmuls = _ida_allins.MC6816_fmuls

MC6816_idiv = _ida_allins.MC6816_idiv

MC6816_mul = _ida_allins.MC6816_mul

MC6816_dec = _ida_allins.MC6816_dec

MC6816_deca = _ida_allins.MC6816_deca

MC6816_decb = _ida_allins.MC6816_decb

MC6816_decw = _ida_allins.MC6816_decw

MC6816_inc = _ida_allins.MC6816_inc

MC6816_inca = _ida_allins.MC6816_inca

MC6816_incb = _ida_allins.MC6816_incb

MC6816_incw = _ida_allins.MC6816_incw

MC6816_clr = _ida_allins.MC6816_clr

MC6816_clra = _ida_allins.MC6816_clra

MC6816_clrb = _ida_allins.MC6816_clrb

MC6816_clrd = _ida_allins.MC6816_clrd

MC6816_clre = _ida_allins.MC6816_clre

MC6816_clrw = _ida_allins.MC6816_clrw

MC6816_com = _ida_allins.MC6816_com

MC6816_coma = _ida_allins.MC6816_coma

MC6816_comb = _ida_allins.MC6816_comb

MC6816_comd = _ida_allins.MC6816_comd

MC6816_come = _ida_allins.MC6816_come

MC6816_comw = _ida_allins.MC6816_comw

MC6816_neg = _ida_allins.MC6816_neg

MC6816_nega = _ida_allins.MC6816_nega

MC6816_negb = _ida_allins.MC6816_negb

MC6816_negd = _ida_allins.MC6816_negd

MC6816_nege = _ida_allins.MC6816_nege

MC6816_negw = _ida_allins.MC6816_negw

MC6816_anda = _ida_allins.MC6816_anda

MC6816_andb = _ida_allins.MC6816_andb

MC6816_andd = _ida_allins.MC6816_andd

MC6816_ande = _ida_allins.MC6816_ande

MC6816_eora = _ida_allins.MC6816_eora

MC6816_eorb = _ida_allins.MC6816_eorb

MC6816_eord = _ida_allins.MC6816_eord

MC6816_eore = _ida_allins.MC6816_eore

MC6816_oraa = _ida_allins.MC6816_oraa

MC6816_orab = _ida_allins.MC6816_orab

MC6816_ord = _ida_allins.MC6816_ord

MC6816_ore = _ida_allins.MC6816_ore

MC6816_bita = _ida_allins.MC6816_bita

MC6816_bitb = _ida_allins.MC6816_bitb

MC6816_bclr = _ida_allins.MC6816_bclr

MC6816_bclrw = _ida_allins.MC6816_bclrw

MC6816_bset = _ida_allins.MC6816_bset

MC6816_bsetw = _ida_allins.MC6816_bsetw

MC6816_lsr = _ida_allins.MC6816_lsr

MC6816_lsra = _ida_allins.MC6816_lsra

MC6816_lsrb = _ida_allins.MC6816_lsrb

MC6816_lsrd = _ida_allins.MC6816_lsrd

MC6816_lsre = _ida_allins.MC6816_lsre

MC6816_lsrw = _ida_allins.MC6816_lsrw

MC6816_asl = _ida_allins.MC6816_asl

MC6816_asla = _ida_allins.MC6816_asla

MC6816_aslb = _ida_allins.MC6816_aslb

MC6816_asld = _ida_allins.MC6816_asld

MC6816_asle = _ida_allins.MC6816_asle

MC6816_aslw = _ida_allins.MC6816_aslw

MC6816_asr = _ida_allins.MC6816_asr

MC6816_asra = _ida_allins.MC6816_asra

MC6816_asrb = _ida_allins.MC6816_asrb

MC6816_asrd = _ida_allins.MC6816_asrd

MC6816_asre = _ida_allins.MC6816_asre

MC6816_asrw = _ida_allins.MC6816_asrw

MC6816_rol = _ida_allins.MC6816_rol

MC6816_rola = _ida_allins.MC6816_rola

MC6816_rolb = _ida_allins.MC6816_rolb

MC6816_rold = _ida_allins.MC6816_rold

MC6816_role = _ida_allins.MC6816_role

MC6816_rolw = _ida_allins.MC6816_rolw

MC6816_ror = _ida_allins.MC6816_ror

MC6816_rora = _ida_allins.MC6816_rora

MC6816_rorb = _ida_allins.MC6816_rorb

MC6816_rord = _ida_allins.MC6816_rord

MC6816_rore = _ida_allins.MC6816_rore

MC6816_rorw = _ida_allins.MC6816_rorw

MC6816_bra = _ida_allins.MC6816_bra

MC6816_brn = _ida_allins.MC6816_brn

MC6816_bcc = _ida_allins.MC6816_bcc

MC6816_bcs = _ida_allins.MC6816_bcs

MC6816_beq = _ida_allins.MC6816_beq

MC6816_bmi = _ida_allins.MC6816_bmi

MC6816_bne = _ida_allins.MC6816_bne

MC6816_bpl = _ida_allins.MC6816_bpl

MC6816_bvc = _ida_allins.MC6816_bvc

MC6816_bvs = _ida_allins.MC6816_bvs

MC6816_bhi = _ida_allins.MC6816_bhi

MC6816_bls = _ida_allins.MC6816_bls

MC6816_bge = _ida_allins.MC6816_bge

MC6816_bgt = _ida_allins.MC6816_bgt

MC6816_ble = _ida_allins.MC6816_ble

MC6816_blt = _ida_allins.MC6816_blt

MC6816_lbra = _ida_allins.MC6816_lbra

MC6816_lbrn = _ida_allins.MC6816_lbrn

MC6816_lbcc = _ida_allins.MC6816_lbcc

MC6816_lbcs = _ida_allins.MC6816_lbcs

MC6816_lbeq = _ida_allins.MC6816_lbeq

MC6816_lbev = _ida_allins.MC6816_lbev

MC6816_lbmi = _ida_allins.MC6816_lbmi

MC6816_lbmv = _ida_allins.MC6816_lbmv

MC6816_lbne = _ida_allins.MC6816_lbne

MC6816_lbpl = _ida_allins.MC6816_lbpl

MC6816_lbvc = _ida_allins.MC6816_lbvc

MC6816_lbvs = _ida_allins.MC6816_lbvs

MC6816_lbhi = _ida_allins.MC6816_lbhi

MC6816_lbls = _ida_allins.MC6816_lbls

MC6816_lbge = _ida_allins.MC6816_lbge

MC6816_lbgt = _ida_allins.MC6816_lbgt

MC6816_lble = _ida_allins.MC6816_lble

MC6816_lblt = _ida_allins.MC6816_lblt

MC6816_brclr = _ida_allins.MC6816_brclr

MC6816_brset = _ida_allins.MC6816_brset

MC6816_jmp = _ida_allins.MC6816_jmp

MC6816_bsr = _ida_allins.MC6816_bsr

MC6816_jsr = _ida_allins.MC6816_jsr

MC6816_lbsr = _ida_allins.MC6816_lbsr

MC6816_rts = _ida_allins.MC6816_rts

MC6816_rti = _ida_allins.MC6816_rti

MC6816_swi = _ida_allins.MC6816_swi

MC6816_abx = _ida_allins.MC6816_abx

MC6816_aby = _ida_allins.MC6816_aby

MC6816_abz = _ida_allins.MC6816_abz

MC6816_adx = _ida_allins.MC6816_adx

MC6816_ady = _ida_allins.MC6816_ady

MC6816_adz = _ida_allins.MC6816_adz

MC6816_aex = _ida_allins.MC6816_aex

MC6816_aey = _ida_allins.MC6816_aey

MC6816_aez = _ida_allins.MC6816_aez

MC6816_aix = _ida_allins.MC6816_aix

MC6816_aiy = _ida_allins.MC6816_aiy

MC6816_aiz = _ida_allins.MC6816_aiz

MC6816_cpx = _ida_allins.MC6816_cpx

MC6816_cpy = _ida_allins.MC6816_cpy

MC6816_cpz = _ida_allins.MC6816_cpz

MC6816_ldx = _ida_allins.MC6816_ldx

MC6816_ldy = _ida_allins.MC6816_ldy

MC6816_ldz = _ida_allins.MC6816_ldz

MC6816_stx = _ida_allins.MC6816_stx

MC6816_sty = _ida_allins.MC6816_sty

MC6816_stz = _ida_allins.MC6816_stz

MC6816_tsx = _ida_allins.MC6816_tsx

MC6816_tsy = _ida_allins.MC6816_tsy

MC6816_tsz = _ida_allins.MC6816_tsz

MC6816_txs = _ida_allins.MC6816_txs

MC6816_txy = _ida_allins.MC6816_txy

MC6816_txz = _ida_allins.MC6816_txz

MC6816_tys = _ida_allins.MC6816_tys

MC6816_tyx = _ida_allins.MC6816_tyx

MC6816_tyz = _ida_allins.MC6816_tyz

MC6816_tzs = _ida_allins.MC6816_tzs

MC6816_tzx = _ida_allins.MC6816_tzx

MC6816_tzy = _ida_allins.MC6816_tzy

MC6816_xgdx = _ida_allins.MC6816_xgdx

MC6816_xgdy = _ida_allins.MC6816_xgdy

MC6816_xgdz = _ida_allins.MC6816_xgdz

MC6816_xgex = _ida_allins.MC6816_xgex

MC6816_xgey = _ida_allins.MC6816_xgey

MC6816_xgez = _ida_allins.MC6816_xgez

MC6816_tbek = _ida_allins.MC6816_tbek

MC6816_tbsk = _ida_allins.MC6816_tbsk

MC6816_tbxk = _ida_allins.MC6816_tbxk

MC6816_tbyk = _ida_allins.MC6816_tbyk

MC6816_tbzk = _ida_allins.MC6816_tbzk

MC6816_tekb = _ida_allins.MC6816_tekb

MC6816_tskb = _ida_allins.MC6816_tskb

MC6816_txkb = _ida_allins.MC6816_txkb

MC6816_tykb = _ida_allins.MC6816_tykb

MC6816_tzkb = _ida_allins.MC6816_tzkb

MC6816_ais = _ida_allins.MC6816_ais

MC6816_cps = _ida_allins.MC6816_cps

MC6816_lds = _ida_allins.MC6816_lds

MC6816_sts = _ida_allins.MC6816_sts

MC6816_psha = _ida_allins.MC6816_psha

MC6816_pshb = _ida_allins.MC6816_pshb

MC6816_pshm = _ida_allins.MC6816_pshm

MC6816_pula = _ida_allins.MC6816_pula

MC6816_pulb = _ida_allins.MC6816_pulb

MC6816_pulm = _ida_allins.MC6816_pulm

MC6816_andp = _ida_allins.MC6816_andp

MC6816_orp = _ida_allins.MC6816_orp

MC6816_tap = _ida_allins.MC6816_tap

MC6816_tdp = _ida_allins.MC6816_tdp

MC6816_tpa = _ida_allins.MC6816_tpa

MC6816_tpd = _ida_allins.MC6816_tpd

MC6816_ace = _ida_allins.MC6816_ace

MC6816_aced = _ida_allins.MC6816_aced

MC6816_aslm = _ida_allins.MC6816_aslm

MC6816_asrm = _ida_allins.MC6816_asrm

MC6816_clrm = _ida_allins.MC6816_clrm

MC6816_ldhi = _ida_allins.MC6816_ldhi

MC6816_mac = _ida_allins.MC6816_mac

MC6816_pshmac = _ida_allins.MC6816_pshmac

MC6816_pulmac = _ida_allins.MC6816_pulmac

MC6816_rmac = _ida_allins.MC6816_rmac

MC6816_tdmsk = _ida_allins.MC6816_tdmsk

MC6816_tedm = _ida_allins.MC6816_tedm

MC6816_tem = _ida_allins.MC6816_tem

MC6816_tmer = _ida_allins.MC6816_tmer

MC6816_tmet = _ida_allins.MC6816_tmet

MC6816_tmxed = _ida_allins.MC6816_tmxed

MC6816_lpstop = _ida_allins.MC6816_lpstop

MC6816_wai = _ida_allins.MC6816_wai

MC6816_bgnd = _ida_allins.MC6816_bgnd

MC6816_nop = _ida_allins.MC6816_nop

MC6816_last = _ida_allins.MC6816_last

I960_null = _ida_allins.I960_null

I960_addc = _ida_allins.I960_addc

I960_addi = _ida_allins.I960_addi

I960_addo = _ida_allins.I960_addo

I960_alterbit = _ida_allins.I960_alterbit

I960_and = _ida_allins.I960_and

I960_andnot = _ida_allins.I960_andnot

I960_atadd = _ida_allins.I960_atadd

I960_atmod = _ida_allins.I960_atmod

I960_b = _ida_allins.I960_b

I960_bal = _ida_allins.I960_bal

I960_balx = _ida_allins.I960_balx

I960_bbc = _ida_allins.I960_bbc

I960_bbs = _ida_allins.I960_bbs

I960_bno = _ida_allins.I960_bno

I960_bg = _ida_allins.I960_bg

I960_be = _ida_allins.I960_be

I960_bge = _ida_allins.I960_bge

I960_bl = _ida_allins.I960_bl

I960_bne = _ida_allins.I960_bne

I960_ble = _ida_allins.I960_ble

I960_bo = _ida_allins.I960_bo

I960_bx = _ida_allins.I960_bx

I960_call = _ida_allins.I960_call

I960_calls = _ida_allins.I960_calls

I960_callx = _ida_allins.I960_callx

I960_chkbit = _ida_allins.I960_chkbit

I960_clrbit = _ida_allins.I960_clrbit

I960_cmpdeci = _ida_allins.I960_cmpdeci

I960_cmpdeco = _ida_allins.I960_cmpdeco

I960_cmpi = _ida_allins.I960_cmpi

I960_cmpibno = _ida_allins.I960_cmpibno

I960_cmpibg = _ida_allins.I960_cmpibg

I960_cmpibe = _ida_allins.I960_cmpibe

I960_cmpibge = _ida_allins.I960_cmpibge

I960_cmpibl = _ida_allins.I960_cmpibl

I960_cmpibne = _ida_allins.I960_cmpibne

I960_cmpible = _ida_allins.I960_cmpible

I960_cmpibo = _ida_allins.I960_cmpibo

I960_cmpinci = _ida_allins.I960_cmpinci

I960_cmpinco = _ida_allins.I960_cmpinco

I960_cmpo = _ida_allins.I960_cmpo

I960_cmpobg = _ida_allins.I960_cmpobg

I960_cmpobe = _ida_allins.I960_cmpobe

I960_cmpobge = _ida_allins.I960_cmpobge

I960_cmpobl = _ida_allins.I960_cmpobl

I960_cmpobne = _ida_allins.I960_cmpobne

I960_cmpoble = _ida_allins.I960_cmpoble

I960_concmpi = _ida_allins.I960_concmpi

I960_concmpo = _ida_allins.I960_concmpo

I960_divi = _ida_allins.I960_divi

I960_divo = _ida_allins.I960_divo

I960_ediv = _ida_allins.I960_ediv

I960_emul = _ida_allins.I960_emul

I960_eshro = _ida_allins.I960_eshro

I960_extract = _ida_allins.I960_extract

I960_faultno = _ida_allins.I960_faultno

I960_faultg = _ida_allins.I960_faultg

I960_faulte = _ida_allins.I960_faulte

I960_faultge = _ida_allins.I960_faultge

I960_faultl = _ida_allins.I960_faultl

I960_faultne = _ida_allins.I960_faultne

I960_faultle = _ida_allins.I960_faultle

I960_faulto = _ida_allins.I960_faulto

I960_flushreg = _ida_allins.I960_flushreg

I960_fmark = _ida_allins.I960_fmark

I960_ld = _ida_allins.I960_ld

I960_lda = _ida_allins.I960_lda

I960_ldib = _ida_allins.I960_ldib

I960_ldis = _ida_allins.I960_ldis

I960_ldl = _ida_allins.I960_ldl

I960_ldob = _ida_allins.I960_ldob

I960_ldos = _ida_allins.I960_ldos

I960_ldq = _ida_allins.I960_ldq

I960_ldt = _ida_allins.I960_ldt

I960_mark = _ida_allins.I960_mark

I960_modac = _ida_allins.I960_modac

I960_modi = _ida_allins.I960_modi

I960_modify = _ida_allins.I960_modify

I960_modpc = _ida_allins.I960_modpc

I960_modtc = _ida_allins.I960_modtc

I960_mov = _ida_allins.I960_mov

I960_movl = _ida_allins.I960_movl

I960_movq = _ida_allins.I960_movq

I960_movt = _ida_allins.I960_movt

I960_muli = _ida_allins.I960_muli

I960_mulo = _ida_allins.I960_mulo

I960_nand = _ida_allins.I960_nand

I960_nor = _ida_allins.I960_nor

I960_not = _ida_allins.I960_not

I960_notand = _ida_allins.I960_notand

I960_notbit = _ida_allins.I960_notbit

I960_notor = _ida_allins.I960_notor

I960_or = _ida_allins.I960_or

I960_ornot = _ida_allins.I960_ornot

I960_remi = _ida_allins.I960_remi

I960_remo = _ida_allins.I960_remo

I960_ret = _ida_allins.I960_ret

I960_rotate = _ida_allins.I960_rotate

I960_scanbit = _ida_allins.I960_scanbit

I960_scanbyte = _ida_allins.I960_scanbyte

I960_setbit = _ida_allins.I960_setbit

I960_shli = _ida_allins.I960_shli

I960_shlo = _ida_allins.I960_shlo

I960_shrdi = _ida_allins.I960_shrdi

I960_shri = _ida_allins.I960_shri

I960_shro = _ida_allins.I960_shro

I960_spanbit = _ida_allins.I960_spanbit

I960_st = _ida_allins.I960_st

I960_stib = _ida_allins.I960_stib

I960_stis = _ida_allins.I960_stis

I960_stl = _ida_allins.I960_stl

I960_stob = _ida_allins.I960_stob

I960_stos = _ida_allins.I960_stos

I960_stq = _ida_allins.I960_stq

I960_stt = _ida_allins.I960_stt

I960_subc = _ida_allins.I960_subc

I960_subi = _ida_allins.I960_subi

I960_subo = _ida_allins.I960_subo

I960_syncf = _ida_allins.I960_syncf

I960_testno = _ida_allins.I960_testno

I960_testg = _ida_allins.I960_testg

I960_teste = _ida_allins.I960_teste

I960_testge = _ida_allins.I960_testge

I960_testl = _ida_allins.I960_testl

I960_testne = _ida_allins.I960_testne

I960_testle = _ida_allins.I960_testle

I960_testo = _ida_allins.I960_testo

I960_xnor = _ida_allins.I960_xnor

I960_xor = _ida_allins.I960_xor

I960_sdma = _ida_allins.I960_sdma

I960_sysctl = _ida_allins.I960_sysctl

I960_udma = _ida_allins.I960_udma

I960_dcinva = _ida_allins.I960_dcinva

I960_cmpob = _ida_allins.I960_cmpob

I960_cmpib = _ida_allins.I960_cmpib

I960_cmpos = _ida_allins.I960_cmpos

I960_cmpis = _ida_allins.I960_cmpis

I960_bswap = _ida_allins.I960_bswap

I960_intdis = _ida_allins.I960_intdis

I960_inten = _ida_allins.I960_inten

I960_synmov = _ida_allins.I960_synmov

I960_synmovl = _ida_allins.I960_synmovl

I960_synmovq = _ida_allins.I960_synmovq

I960_cmpstr = _ida_allins.I960_cmpstr

I960_movqstr = _ida_allins.I960_movqstr

I960_movstr = _ida_allins.I960_movstr

I960_inspacc = _ida_allins.I960_inspacc

I960_ldphy = _ida_allins.I960_ldphy

I960_synld = _ida_allins.I960_synld

I960_fill = _ida_allins.I960_fill

I960_daddc = _ida_allins.I960_daddc

I960_dsubc = _ida_allins.I960_dsubc

I960_dmovt = _ida_allins.I960_dmovt

I960_condrec = _ida_allins.I960_condrec

I960_receive = _ida_allins.I960_receive

I960_intctl = _ida_allins.I960_intctl

I960_icctl = _ida_allins.I960_icctl

I960_dcctl = _ida_allins.I960_dcctl

I960_halt = _ida_allins.I960_halt

I960_send = _ida_allins.I960_send

I960_sendserv = _ida_allins.I960_sendserv

I960_resumprcs = _ida_allins.I960_resumprcs

I960_schedprcs = _ida_allins.I960_schedprcs

I960_saveprcs = _ida_allins.I960_saveprcs

I960_condwait = _ida_allins.I960_condwait

I960_wait = _ida_allins.I960_wait

I960_signal = _ida_allins.I960_signal

I960_ldtime = _ida_allins.I960_ldtime

I960_addono = _ida_allins.I960_addono

I960_addino = _ida_allins.I960_addino

I960_subono = _ida_allins.I960_subono

I960_subino = _ida_allins.I960_subino

I960_selno = _ida_allins.I960_selno

I960_addog = _ida_allins.I960_addog

I960_addig = _ida_allins.I960_addig

I960_subog = _ida_allins.I960_subog

I960_subig = _ida_allins.I960_subig

I960_selg = _ida_allins.I960_selg

I960_addoe = _ida_allins.I960_addoe

I960_addie = _ida_allins.I960_addie

I960_suboe = _ida_allins.I960_suboe

I960_subie = _ida_allins.I960_subie

I960_sele = _ida_allins.I960_sele

I960_addoge = _ida_allins.I960_addoge

I960_addige = _ida_allins.I960_addige

I960_suboge = _ida_allins.I960_suboge

I960_subige = _ida_allins.I960_subige

I960_selge = _ida_allins.I960_selge

I960_addol = _ida_allins.I960_addol

I960_addil = _ida_allins.I960_addil

I960_subol = _ida_allins.I960_subol

I960_subil = _ida_allins.I960_subil

I960_sell = _ida_allins.I960_sell

I960_addone = _ida_allins.I960_addone

I960_addine = _ida_allins.I960_addine

I960_subone = _ida_allins.I960_subone

I960_subine = _ida_allins.I960_subine

I960_selne = _ida_allins.I960_selne

I960_addole = _ida_allins.I960_addole

I960_addile = _ida_allins.I960_addile

I960_subole = _ida_allins.I960_subole

I960_subile = _ida_allins.I960_subile

I960_selle = _ida_allins.I960_selle

I960_addoo = _ida_allins.I960_addoo

I960_addio = _ida_allins.I960_addio

I960_suboo = _ida_allins.I960_suboo

I960_subio = _ida_allins.I960_subio

I960_selo = _ida_allins.I960_selo

I960_faddr = _ida_allins.I960_faddr

I960_fp_first = _ida_allins.I960_fp_first

I960_faddrl = _ida_allins.I960_faddrl

I960_fatanr = _ida_allins.I960_fatanr

I960_fatanrl = _ida_allins.I960_fatanrl

I960_fclassr = _ida_allins.I960_fclassr

I960_fclassrl = _ida_allins.I960_fclassrl

I960_fcmpor = _ida_allins.I960_fcmpor

I960_fcmporl = _ida_allins.I960_fcmporl

I960_fcmpr = _ida_allins.I960_fcmpr

I960_fcmprl = _ida_allins.I960_fcmprl

I960_fcosr = _ida_allins.I960_fcosr

I960_fcosrl = _ida_allins.I960_fcosrl

I960_fcpyrsre = _ida_allins.I960_fcpyrsre

I960_fcpysre = _ida_allins.I960_fcpysre

I960_fcvtilr = _ida_allins.I960_fcvtilr

I960_fcvtir = _ida_allins.I960_fcvtir

I960_fcvtri = _ida_allins.I960_fcvtri

I960_fcvtril = _ida_allins.I960_fcvtril

I960_fcvtzri = _ida_allins.I960_fcvtzri

I960_fcvtzril = _ida_allins.I960_fcvtzril

I960_fdivr = _ida_allins.I960_fdivr

I960_fdivrl = _ida_allins.I960_fdivrl

I960_fexpr = _ida_allins.I960_fexpr

I960_fexprl = _ida_allins.I960_fexprl

I960_flogbnr = _ida_allins.I960_flogbnr

I960_flogbnrl = _ida_allins.I960_flogbnrl

I960_flogepr = _ida_allins.I960_flogepr

I960_flogeprl = _ida_allins.I960_flogeprl

I960_flogr = _ida_allins.I960_flogr

I960_flogrl = _ida_allins.I960_flogrl

I960_fmovr = _ida_allins.I960_fmovr

I960_fmovre = _ida_allins.I960_fmovre

I960_fmovrl = _ida_allins.I960_fmovrl

I960_fmulr = _ida_allins.I960_fmulr

I960_fmulrl = _ida_allins.I960_fmulrl

I960_fremr = _ida_allins.I960_fremr

I960_fremrl = _ida_allins.I960_fremrl

I960_froundr = _ida_allins.I960_froundr

I960_froundrl = _ida_allins.I960_froundrl

I960_fscaler = _ida_allins.I960_fscaler

I960_fscalerl = _ida_allins.I960_fscalerl

I960_fsinr = _ida_allins.I960_fsinr

I960_fsinrl = _ida_allins.I960_fsinrl

I960_fsqrtr = _ida_allins.I960_fsqrtr

I960_fsqrtrl = _ida_allins.I960_fsqrtrl

I960_fsubr = _ida_allins.I960_fsubr

I960_fsubrl = _ida_allins.I960_fsubrl

I960_ftanr = _ida_allins.I960_ftanr

I960_ftanrl = _ida_allins.I960_ftanrl

I960_fp_last = _ida_allins.I960_fp_last

I960_last = _ida_allins.I960_last

F2MC_null = _ida_allins.F2MC_null

F2MC_mov = _ida_allins.F2MC_mov

F2MC_movn = _ida_allins.F2MC_movn

F2MC_movx = _ida_allins.F2MC_movx

F2MC_xch = _ida_allins.F2MC_xch

F2MC_movw = _ida_allins.F2MC_movw

F2MC_xchw = _ida_allins.F2MC_xchw

F2MC_movl = _ida_allins.F2MC_movl

F2MC_add = _ida_allins.F2MC_add

F2MC_addc1 = _ida_allins.F2MC_addc1

F2MC_addc2 = _ida_allins.F2MC_addc2

F2MC_adddc = _ida_allins.F2MC_adddc

F2MC_sub = _ida_allins.F2MC_sub

F2MC_subc1 = _ida_allins.F2MC_subc1

F2MC_subc2 = _ida_allins.F2MC_subc2

F2MC_subdc = _ida_allins.F2MC_subdc

F2MC_addw1 = _ida_allins.F2MC_addw1

F2MC_addw2 = _ida_allins.F2MC_addw2

F2MC_addcw = _ida_allins.F2MC_addcw

F2MC_subw1 = _ida_allins.F2MC_subw1

F2MC_subw2 = _ida_allins.F2MC_subw2

F2MC_subcw = _ida_allins.F2MC_subcw

F2MC_addl = _ida_allins.F2MC_addl

F2MC_subl = _ida_allins.F2MC_subl

F2MC_inc = _ida_allins.F2MC_inc

F2MC_dec = _ida_allins.F2MC_dec

F2MC_incw = _ida_allins.F2MC_incw

F2MC_decw = _ida_allins.F2MC_decw

F2MC_incl = _ida_allins.F2MC_incl

F2MC_decl = _ida_allins.F2MC_decl

F2MC_cmp1 = _ida_allins.F2MC_cmp1

F2MC_cmp2 = _ida_allins.F2MC_cmp2

F2MC_cmpw1 = _ida_allins.F2MC_cmpw1

F2MC_cmpw2 = _ida_allins.F2MC_cmpw2

F2MC_cmpl = _ida_allins.F2MC_cmpl

F2MC_divu1 = _ida_allins.F2MC_divu1

F2MC_divu2 = _ida_allins.F2MC_divu2

F2MC_divuw = _ida_allins.F2MC_divuw

F2MC_mulu1 = _ida_allins.F2MC_mulu1

F2MC_mulu2 = _ida_allins.F2MC_mulu2

F2MC_muluw1 = _ida_allins.F2MC_muluw1

F2MC_muluw2 = _ida_allins.F2MC_muluw2

F2MC_div1 = _ida_allins.F2MC_div1

F2MC_div2 = _ida_allins.F2MC_div2

F2MC_divw = _ida_allins.F2MC_divw

F2MC_mul1 = _ida_allins.F2MC_mul1

F2MC_mul2 = _ida_allins.F2MC_mul2

F2MC_mulw1 = _ida_allins.F2MC_mulw1

F2MC_mulw2 = _ida_allins.F2MC_mulw2

F2MC_and = _ida_allins.F2MC_and

F2MC_or = _ida_allins.F2MC_or

F2MC_xor = _ida_allins.F2MC_xor

F2MC_not = _ida_allins.F2MC_not

F2MC_andw1 = _ida_allins.F2MC_andw1

F2MC_andw2 = _ida_allins.F2MC_andw2

F2MC_orw1 = _ida_allins.F2MC_orw1

F2MC_orw2 = _ida_allins.F2MC_orw2

F2MC_xorw1 = _ida_allins.F2MC_xorw1

F2MC_xorw2 = _ida_allins.F2MC_xorw2

F2MC_notw = _ida_allins.F2MC_notw

F2MC_andl = _ida_allins.F2MC_andl

F2MC_orl = _ida_allins.F2MC_orl

F2MC_xorl = _ida_allins.F2MC_xorl

F2MC_neg = _ida_allins.F2MC_neg

F2MC_negw = _ida_allins.F2MC_negw

F2MC_nrml = _ida_allins.F2MC_nrml

F2MC_rorc = _ida_allins.F2MC_rorc

F2MC_rolc = _ida_allins.F2MC_rolc

F2MC_asr = _ida_allins.F2MC_asr

F2MC_lsr = _ida_allins.F2MC_lsr

F2MC_lsl = _ida_allins.F2MC_lsl

F2MC_asrw1 = _ida_allins.F2MC_asrw1

F2MC_asrw2 = _ida_allins.F2MC_asrw2

F2MC_lsrw1 = _ida_allins.F2MC_lsrw1

F2MC_lsrw2 = _ida_allins.F2MC_lsrw2

F2MC_lslw1 = _ida_allins.F2MC_lslw1

F2MC_lslw2 = _ida_allins.F2MC_lslw2

F2MC_asrl = _ida_allins.F2MC_asrl

F2MC_lsrl = _ida_allins.F2MC_lsrl

F2MC_lsll = _ida_allins.F2MC_lsll

F2MC_bz = _ida_allins.F2MC_bz

F2MC_bnz = _ida_allins.F2MC_bnz

F2MC_bc = _ida_allins.F2MC_bc

F2MC_bnc = _ida_allins.F2MC_bnc

F2MC_bn = _ida_allins.F2MC_bn

F2MC_bp = _ida_allins.F2MC_bp

F2MC_bv = _ida_allins.F2MC_bv

F2MC_bnv = _ida_allins.F2MC_bnv

F2MC_bt = _ida_allins.F2MC_bt

F2MC_bnt = _ida_allins.F2MC_bnt

F2MC_blt = _ida_allins.F2MC_blt

F2MC_bge = _ida_allins.F2MC_bge

F2MC_ble = _ida_allins.F2MC_ble

F2MC_bgt = _ida_allins.F2MC_bgt

F2MC_bls = _ida_allins.F2MC_bls

F2MC_bhi = _ida_allins.F2MC_bhi

F2MC_bra = _ida_allins.F2MC_bra

F2MC_jmp = _ida_allins.F2MC_jmp

F2MC_jmpp = _ida_allins.F2MC_jmpp

F2MC_call = _ida_allins.F2MC_call

F2MC_callv = _ida_allins.F2MC_callv

F2MC_callp = _ida_allins.F2MC_callp

F2MC_cbne = _ida_allins.F2MC_cbne

F2MC_cwbne = _ida_allins.F2MC_cwbne

F2MC_dbnz = _ida_allins.F2MC_dbnz

F2MC_dwbnz = _ida_allins.F2MC_dwbnz

F2MC_int = _ida_allins.F2MC_int

F2MC_intp = _ida_allins.F2MC_intp

F2MC_int9 = _ida_allins.F2MC_int9

F2MC_reti = _ida_allins.F2MC_reti

F2MC_link = _ida_allins.F2MC_link

F2MC_unlink = _ida_allins.F2MC_unlink

F2MC_ret = _ida_allins.F2MC_ret

F2MC_retp = _ida_allins.F2MC_retp

F2MC_pushw = _ida_allins.F2MC_pushw

F2MC_popw = _ida_allins.F2MC_popw

F2MC_jctx = _ida_allins.F2MC_jctx

F2MC_movea = _ida_allins.F2MC_movea

F2MC_addsp = _ida_allins.F2MC_addsp

F2MC_nop = _ida_allins.F2MC_nop

F2MC_adb = _ida_allins.F2MC_adb

F2MC_dtb = _ida_allins.F2MC_dtb

F2MC_pcb = _ida_allins.F2MC_pcb

F2MC_spb = _ida_allins.F2MC_spb

F2MC_ncc = _ida_allins.F2MC_ncc

F2MC_cmr = _ida_allins.F2MC_cmr

F2MC_movb = _ida_allins.F2MC_movb

F2MC_setb = _ida_allins.F2MC_setb

F2MC_clrb = _ida_allins.F2MC_clrb

F2MC_bbc = _ida_allins.F2MC_bbc

F2MC_bbs = _ida_allins.F2MC_bbs

F2MC_sbbs = _ida_allins.F2MC_sbbs

F2MC_wbts = _ida_allins.F2MC_wbts

F2MC_wbtc = _ida_allins.F2MC_wbtc

F2MC_swap = _ida_allins.F2MC_swap

F2MC_swapw = _ida_allins.F2MC_swapw

F2MC_ext = _ida_allins.F2MC_ext

F2MC_extw = _ida_allins.F2MC_extw

F2MC_zext = _ida_allins.F2MC_zext

F2MC_zextw = _ida_allins.F2MC_zextw

F2MC_movsi = _ida_allins.F2MC_movsi

F2MC_movsd = _ida_allins.F2MC_movsd

F2MC_sceqi = _ida_allins.F2MC_sceqi

F2MC_sceqd = _ida_allins.F2MC_sceqd

F2MC_filsi = _ida_allins.F2MC_filsi

F2MC_movswi = _ida_allins.F2MC_movswi

F2MC_movswd = _ida_allins.F2MC_movswd

F2MC_scweqi = _ida_allins.F2MC_scweqi

F2MC_scweqd = _ida_allins.F2MC_scweqd

F2MC_filswi = _ida_allins.F2MC_filswi

F2MC_bz16 = _ida_allins.F2MC_bz16

F2MC_bnz16 = _ida_allins.F2MC_bnz16

F2MC_bc16 = _ida_allins.F2MC_bc16

F2MC_bnc16 = _ida_allins.F2MC_bnc16

F2MC_bn16 = _ida_allins.F2MC_bn16

F2MC_bp16 = _ida_allins.F2MC_bp16

F2MC_bv16 = _ida_allins.F2MC_bv16

F2MC_bnv16 = _ida_allins.F2MC_bnv16

F2MC_bt16 = _ida_allins.F2MC_bt16

F2MC_bnt16 = _ida_allins.F2MC_bnt16

F2MC_blt16 = _ida_allins.F2MC_blt16

F2MC_bge16 = _ida_allins.F2MC_bge16

F2MC_ble16 = _ida_allins.F2MC_ble16

F2MC_bgt16 = _ida_allins.F2MC_bgt16

F2MC_bls16 = _ida_allins.F2MC_bls16

F2MC_bhi16 = _ida_allins.F2MC_bhi16

F2MC_cbne16 = _ida_allins.F2MC_cbne16

F2MC_cwbne16 = _ida_allins.F2MC_cwbne16

F2MC_dbnz16 = _ida_allins.F2MC_dbnz16

F2MC_dwbnz16 = _ida_allins.F2MC_dwbnz16

F2MC_bbc16 = _ida_allins.F2MC_bbc16

F2MC_bbs16 = _ida_allins.F2MC_bbs16

F2MC_sbbs16 = _ida_allins.F2MC_sbbs16

F2MC_last = _ida_allins.F2MC_last

TMS320C3X_null = _ida_allins.TMS320C3X_null

TMS320C3X_ABSF = _ida_allins.TMS320C3X_ABSF

TMS320C3X_ABSI = _ida_allins.TMS320C3X_ABSI

TMS320C3X_ADDC = _ida_allins.TMS320C3X_ADDC

TMS320C3X_ADDF = _ida_allins.TMS320C3X_ADDF

TMS320C3X_ADDI = _ida_allins.TMS320C3X_ADDI

TMS320C3X_AND = _ida_allins.TMS320C3X_AND

TMS320C3X_ANDN = _ida_allins.TMS320C3X_ANDN

TMS320C3X_ASH = _ida_allins.TMS320C3X_ASH

TMS320C3X_CMPF = _ida_allins.TMS320C3X_CMPF

TMS320C3X_CMPI = _ida_allins.TMS320C3X_CMPI

TMS320C3X_FIX = _ida_allins.TMS320C3X_FIX

TMS320C3X_FLOAT = _ida_allins.TMS320C3X_FLOAT

TMS320C3X_IDLE = _ida_allins.TMS320C3X_IDLE

TMS320C3X_IDLE2 = _ida_allins.TMS320C3X_IDLE2

TMS320C3X_LDE = _ida_allins.TMS320C3X_LDE

TMS320C3X_LDF = _ida_allins.TMS320C3X_LDF

TMS320C3X_LDFI = _ida_allins.TMS320C3X_LDFI

TMS320C3X_LDI = _ida_allins.TMS320C3X_LDI

TMS320C3X_LDII = _ida_allins.TMS320C3X_LDII

TMS320C3X_LDM = _ida_allins.TMS320C3X_LDM

TMS320C3X_LSH = _ida_allins.TMS320C3X_LSH

TMS320C3X_MPYF = _ida_allins.TMS320C3X_MPYF

TMS320C3X_MPYI = _ida_allins.TMS320C3X_MPYI

TMS320C3X_NEGB = _ida_allins.TMS320C3X_NEGB

TMS320C3X_NEGF = _ida_allins.TMS320C3X_NEGF

TMS320C3X_NEGI = _ida_allins.TMS320C3X_NEGI

TMS320C3X_NOP = _ida_allins.TMS320C3X_NOP

TMS320C3X_NORM = _ida_allins.TMS320C3X_NORM

TMS320C3X_NOT = _ida_allins.TMS320C3X_NOT

TMS320C3X_POP = _ida_allins.TMS320C3X_POP

TMS320C3X_POPF = _ida_allins.TMS320C3X_POPF

TMS320C3X_PUSH = _ida_allins.TMS320C3X_PUSH

TMS320C3X_PUSHF = _ida_allins.TMS320C3X_PUSHF

TMS320C3X_OR = _ida_allins.TMS320C3X_OR

TMS320C3X_LOPOWER = _ida_allins.TMS320C3X_LOPOWER

TMS320C3X_MAXSPEED = _ida_allins.TMS320C3X_MAXSPEED

TMS320C3X_RND = _ida_allins.TMS320C3X_RND

TMS320C3X_ROL = _ida_allins.TMS320C3X_ROL

TMS320C3X_ROLC = _ida_allins.TMS320C3X_ROLC

TMS320C3X_ROR = _ida_allins.TMS320C3X_ROR

TMS320C3X_RORC = _ida_allins.TMS320C3X_RORC

TMS320C3X_RPTS = _ida_allins.TMS320C3X_RPTS

TMS320C3X_STF = _ida_allins.TMS320C3X_STF

TMS320C3X_STFI = _ida_allins.TMS320C3X_STFI

TMS320C3X_STI = _ida_allins.TMS320C3X_STI

TMS320C3X_STII = _ida_allins.TMS320C3X_STII

TMS320C3X_SIGI = _ida_allins.TMS320C3X_SIGI

TMS320C3X_SUBB = _ida_allins.TMS320C3X_SUBB

TMS320C3X_SUBC = _ida_allins.TMS320C3X_SUBC

TMS320C3X_SUBF = _ida_allins.TMS320C3X_SUBF

TMS320C3X_SUBI = _ida_allins.TMS320C3X_SUBI

TMS320C3X_SUBRB = _ida_allins.TMS320C3X_SUBRB

TMS320C3X_SUBRF = _ida_allins.TMS320C3X_SUBRF

TMS320C3X_SUBRI = _ida_allins.TMS320C3X_SUBRI

TMS320C3X_TSTB = _ida_allins.TMS320C3X_TSTB

TMS320C3X_XOR = _ida_allins.TMS320C3X_XOR

TMS320C3X_IACK = _ida_allins.TMS320C3X_IACK

TMS320C3X_ADDC3 = _ida_allins.TMS320C3X_ADDC3

TMS320C3X_ADDF3 = _ida_allins.TMS320C3X_ADDF3

TMS320C3X_ADDI3 = _ida_allins.TMS320C3X_ADDI3

TMS320C3X_AND3 = _ida_allins.TMS320C3X_AND3

TMS320C3X_ANDN3 = _ida_allins.TMS320C3X_ANDN3

TMS320C3X_ASH3 = _ida_allins.TMS320C3X_ASH3

TMS320C3X_CMPF3 = _ida_allins.TMS320C3X_CMPF3

TMS320C3X_CMPI3 = _ida_allins.TMS320C3X_CMPI3

TMS320C3X_LSH3 = _ida_allins.TMS320C3X_LSH3

TMS320C3X_MPYF3 = _ida_allins.TMS320C3X_MPYF3

TMS320C3X_MPYI3 = _ida_allins.TMS320C3X_MPYI3

TMS320C3X_OR3 = _ida_allins.TMS320C3X_OR3

TMS320C3X_SUBB3 = _ida_allins.TMS320C3X_SUBB3

TMS320C3X_SUBF3 = _ida_allins.TMS320C3X_SUBF3

TMS320C3X_SUBI3 = _ida_allins.TMS320C3X_SUBI3

TMS320C3X_TSTB3 = _ida_allins.TMS320C3X_TSTB3

TMS320C3X_XOR3 = _ida_allins.TMS320C3X_XOR3

TMS320C3X_LDFcond = _ida_allins.TMS320C3X_LDFcond

TMS320C3X_LDIcond = _ida_allins.TMS320C3X_LDIcond

TMS320C3X_BR = _ida_allins.TMS320C3X_BR

TMS320C3X_BRD = _ida_allins.TMS320C3X_BRD

TMS320C3X_CALL = _ida_allins.TMS320C3X_CALL

TMS320C3X_RPTB = _ida_allins.TMS320C3X_RPTB

TMS320C3X_SWI = _ida_allins.TMS320C3X_SWI

TMS320C3X_Bcond = _ida_allins.TMS320C3X_Bcond

TMS320C3X_DBcond = _ida_allins.TMS320C3X_DBcond

TMS320C3X_CALLcond = _ida_allins.TMS320C3X_CALLcond

TMS320C3X_TRAPcond = _ida_allins.TMS320C3X_TRAPcond

TMS320C3X_RETIcond = _ida_allins.TMS320C3X_RETIcond

TMS320C3X_RETScond = _ida_allins.TMS320C3X_RETScond

TMS320C3X_RETIU = _ida_allins.TMS320C3X_RETIU

TMS320C3X_RETSU = _ida_allins.TMS320C3X_RETSU

TMS320C3X_NONE = _ida_allins.TMS320C3X_NONE

TMS320C3X_MV_IDX = _ida_allins.TMS320C3X_MV_IDX

TMS320C3X_last = _ida_allins.TMS320C3X_last

TMS320C54_null = _ida_allins.TMS320C54_null

TMS320C54_add1 = _ida_allins.TMS320C54_add1

TMS320C54_add2 = _ida_allins.TMS320C54_add2

TMS320C54_add3 = _ida_allins.TMS320C54_add3

TMS320C54_addc = _ida_allins.TMS320C54_addc

TMS320C54_addm = _ida_allins.TMS320C54_addm

TMS320C54_adds = _ida_allins.TMS320C54_adds

TMS320C54_sub1 = _ida_allins.TMS320C54_sub1

TMS320C54_sub2 = _ida_allins.TMS320C54_sub2

TMS320C54_sub3 = _ida_allins.TMS320C54_sub3

TMS320C54_subb = _ida_allins.TMS320C54_subb

TMS320C54_subc = _ida_allins.TMS320C54_subc

TMS320C54_subs = _ida_allins.TMS320C54_subs

TMS320C54_mpy2 = _ida_allins.TMS320C54_mpy2

TMS320C54_mpy3 = _ida_allins.TMS320C54_mpy3

TMS320C54_mpyr2 = _ida_allins.TMS320C54_mpyr2

TMS320C54_mpya = _ida_allins.TMS320C54_mpya

TMS320C54_mpyu = _ida_allins.TMS320C54_mpyu

TMS320C54_squr = _ida_allins.TMS320C54_squr

TMS320C54_mac2 = _ida_allins.TMS320C54_mac2

TMS320C54_mac3 = _ida_allins.TMS320C54_mac3

TMS320C54_macr2 = _ida_allins.TMS320C54_macr2

TMS320C54_macr3 = _ida_allins.TMS320C54_macr3

TMS320C54_maca1 = _ida_allins.TMS320C54_maca1

TMS320C54_maca2 = _ida_allins.TMS320C54_maca2

TMS320C54_maca3 = _ida_allins.TMS320C54_maca3

TMS320C54_macar1 = _ida_allins.TMS320C54_macar1

TMS320C54_macar2 = _ida_allins.TMS320C54_macar2

TMS320C54_macar3 = _ida_allins.TMS320C54_macar3

TMS320C54_macd = _ida_allins.TMS320C54_macd

TMS320C54_macp = _ida_allins.TMS320C54_macp

TMS320C54_macsu = _ida_allins.TMS320C54_macsu

TMS320C54_mas2 = _ida_allins.TMS320C54_mas2

TMS320C54_mas3 = _ida_allins.TMS320C54_mas3

TMS320C54_masr2 = _ida_allins.TMS320C54_masr2

TMS320C54_masr3 = _ida_allins.TMS320C54_masr3

TMS320C54_masa1 = _ida_allins.TMS320C54_masa1

TMS320C54_masa2 = _ida_allins.TMS320C54_masa2

TMS320C54_masa3 = _ida_allins.TMS320C54_masa3

TMS320C54_masar1 = _ida_allins.TMS320C54_masar1

TMS320C54_masar2 = _ida_allins.TMS320C54_masar2

TMS320C54_masar3 = _ida_allins.TMS320C54_masar3

TMS320C54_squra = _ida_allins.TMS320C54_squra

TMS320C54_squrs = _ida_allins.TMS320C54_squrs

TMS320C54_dadd2 = _ida_allins.TMS320C54_dadd2

TMS320C54_dadd3 = _ida_allins.TMS320C54_dadd3

TMS320C54_dadst = _ida_allins.TMS320C54_dadst

TMS320C54_drsub = _ida_allins.TMS320C54_drsub

TMS320C54_dsadt = _ida_allins.TMS320C54_dsadt

TMS320C54_dsub = _ida_allins.TMS320C54_dsub

TMS320C54_dsubt = _ida_allins.TMS320C54_dsubt

TMS320C54_abdst = _ida_allins.TMS320C54_abdst

TMS320C54_abs1 = _ida_allins.TMS320C54_abs1

TMS320C54_abs2 = _ida_allins.TMS320C54_abs2

TMS320C54_cmpl1 = _ida_allins.TMS320C54_cmpl1

TMS320C54_cmpl2 = _ida_allins.TMS320C54_cmpl2

TMS320C54_delay = _ida_allins.TMS320C54_delay

TMS320C54_exp = _ida_allins.TMS320C54_exp

TMS320C54_firs = _ida_allins.TMS320C54_firs

TMS320C54_lms = _ida_allins.TMS320C54_lms

TMS320C54_max = _ida_allins.TMS320C54_max

TMS320C54_min = _ida_allins.TMS320C54_min

TMS320C54_neg1 = _ida_allins.TMS320C54_neg1

TMS320C54_neg2 = _ida_allins.TMS320C54_neg2

TMS320C54_norm1 = _ida_allins.TMS320C54_norm1

TMS320C54_norm2 = _ida_allins.TMS320C54_norm2

TMS320C54_poly = _ida_allins.TMS320C54_poly

TMS320C54_rnd1 = _ida_allins.TMS320C54_rnd1

TMS320C54_rnd2 = _ida_allins.TMS320C54_rnd2

TMS320C54_sat = _ida_allins.TMS320C54_sat

TMS320C54_sqdst = _ida_allins.TMS320C54_sqdst

TMS320C54_and1 = _ida_allins.TMS320C54_and1

TMS320C54_and2 = _ida_allins.TMS320C54_and2

TMS320C54_and3 = _ida_allins.TMS320C54_and3

TMS320C54_andm = _ida_allins.TMS320C54_andm

TMS320C54_or1 = _ida_allins.TMS320C54_or1

TMS320C54_or2 = _ida_allins.TMS320C54_or2

TMS320C54_or3 = _ida_allins.TMS320C54_or3

TMS320C54_orm = _ida_allins.TMS320C54_orm

TMS320C54_xor1 = _ida_allins.TMS320C54_xor1

TMS320C54_xor2 = _ida_allins.TMS320C54_xor2

TMS320C54_xor3 = _ida_allins.TMS320C54_xor3

TMS320C54_xorm = _ida_allins.TMS320C54_xorm

TMS320C54_rol = _ida_allins.TMS320C54_rol

TMS320C54_roltc = _ida_allins.TMS320C54_roltc

TMS320C54_ror = _ida_allins.TMS320C54_ror

TMS320C54_sfta2 = _ida_allins.TMS320C54_sfta2

TMS320C54_sfta3 = _ida_allins.TMS320C54_sfta3

TMS320C54_sftc = _ida_allins.TMS320C54_sftc

TMS320C54_sftl2 = _ida_allins.TMS320C54_sftl2

TMS320C54_sftl3 = _ida_allins.TMS320C54_sftl3

TMS320C54_bit = _ida_allins.TMS320C54_bit

TMS320C54_bitf = _ida_allins.TMS320C54_bitf

TMS320C54_bitt = _ida_allins.TMS320C54_bitt

TMS320C54_cmpm = _ida_allins.TMS320C54_cmpm

TMS320C54_cmpr = _ida_allins.TMS320C54_cmpr

TMS320C54_b = _ida_allins.TMS320C54_b

TMS320C54_bd = _ida_allins.TMS320C54_bd

TMS320C54_bacc = _ida_allins.TMS320C54_bacc

TMS320C54_baccd = _ida_allins.TMS320C54_baccd

TMS320C54_banz = _ida_allins.TMS320C54_banz

TMS320C54_banzd = _ida_allins.TMS320C54_banzd

TMS320C54_bc2 = _ida_allins.TMS320C54_bc2

TMS320C54_bc3 = _ida_allins.TMS320C54_bc3

TMS320C54_bcd2 = _ida_allins.TMS320C54_bcd2

TMS320C54_bcd3 = _ida_allins.TMS320C54_bcd3

TMS320C54_fb = _ida_allins.TMS320C54_fb

TMS320C54_fbd = _ida_allins.TMS320C54_fbd

TMS320C54_fbacc = _ida_allins.TMS320C54_fbacc

TMS320C54_fbaccd = _ida_allins.TMS320C54_fbaccd

TMS320C54_cala = _ida_allins.TMS320C54_cala

TMS320C54_calad = _ida_allins.TMS320C54_calad

TMS320C54_call = _ida_allins.TMS320C54_call

TMS320C54_calld = _ida_allins.TMS320C54_calld

TMS320C54_cc2 = _ida_allins.TMS320C54_cc2

TMS320C54_cc3 = _ida_allins.TMS320C54_cc3

TMS320C54_ccd2 = _ida_allins.TMS320C54_ccd2

TMS320C54_ccd3 = _ida_allins.TMS320C54_ccd3

TMS320C54_fcala = _ida_allins.TMS320C54_fcala

TMS320C54_fcalad = _ida_allins.TMS320C54_fcalad

TMS320C54_fcall = _ida_allins.TMS320C54_fcall

TMS320C54_fcalld = _ida_allins.TMS320C54_fcalld

TMS320C54_intr = _ida_allins.TMS320C54_intr

TMS320C54_trap = _ida_allins.TMS320C54_trap

TMS320C54_fret = _ida_allins.TMS320C54_fret

TMS320C54_fretd = _ida_allins.TMS320C54_fretd

TMS320C54_frete = _ida_allins.TMS320C54_frete

TMS320C54_freted = _ida_allins.TMS320C54_freted

TMS320C54_rc1 = _ida_allins.TMS320C54_rc1

TMS320C54_rc2 = _ida_allins.TMS320C54_rc2

TMS320C54_rc3 = _ida_allins.TMS320C54_rc3

TMS320C54_rcd1 = _ida_allins.TMS320C54_rcd1

TMS320C54_rcd2 = _ida_allins.TMS320C54_rcd2

TMS320C54_rcd3 = _ida_allins.TMS320C54_rcd3

TMS320C54_ret = _ida_allins.TMS320C54_ret

TMS320C54_retd = _ida_allins.TMS320C54_retd

TMS320C54_rete = _ida_allins.TMS320C54_rete

TMS320C54_reted = _ida_allins.TMS320C54_reted

TMS320C54_retf = _ida_allins.TMS320C54_retf

TMS320C54_retfd = _ida_allins.TMS320C54_retfd

TMS320C54_rpt = _ida_allins.TMS320C54_rpt

TMS320C54_rptb = _ida_allins.TMS320C54_rptb

TMS320C54_rptbd = _ida_allins.TMS320C54_rptbd

TMS320C54_rptz = _ida_allins.TMS320C54_rptz

TMS320C54_frame = _ida_allins.TMS320C54_frame

TMS320C54_popd = _ida_allins.TMS320C54_popd

TMS320C54_popm = _ida_allins.TMS320C54_popm

TMS320C54_pshd = _ida_allins.TMS320C54_pshd

TMS320C54_pshm = _ida_allins.TMS320C54_pshm

TMS320C54_idle = _ida_allins.TMS320C54_idle

TMS320C54_mar = _ida_allins.TMS320C54_mar

TMS320C54_nop = _ida_allins.TMS320C54_nop

TMS320C54_reset = _ida_allins.TMS320C54_reset

TMS320C54_rsbx1 = _ida_allins.TMS320C54_rsbx1

TMS320C54_rsbx2 = _ida_allins.TMS320C54_rsbx2

TMS320C54_ssbx1 = _ida_allins.TMS320C54_ssbx1

TMS320C54_ssbx2 = _ida_allins.TMS320C54_ssbx2

TMS320C54_xc2 = _ida_allins.TMS320C54_xc2

TMS320C54_xc3 = _ida_allins.TMS320C54_xc3

TMS320C54_dld = _ida_allins.TMS320C54_dld

TMS320C54_ld1 = _ida_allins.TMS320C54_ld1

TMS320C54_ld2 = _ida_allins.TMS320C54_ld2

TMS320C54_ld3 = _ida_allins.TMS320C54_ld3

TMS320C54_ldm = _ida_allins.TMS320C54_ldm

TMS320C54_ldr = _ida_allins.TMS320C54_ldr

TMS320C54_ldu = _ida_allins.TMS320C54_ldu

TMS320C54_ltd = _ida_allins.TMS320C54_ltd

TMS320C54_dst = _ida_allins.TMS320C54_dst

TMS320C54_st = _ida_allins.TMS320C54_st

TMS320C54_sth2 = _ida_allins.TMS320C54_sth2

TMS320C54_sth3 = _ida_allins.TMS320C54_sth3

TMS320C54_stl2 = _ida_allins.TMS320C54_stl2

TMS320C54_stl3 = _ida_allins.TMS320C54_stl3

TMS320C54_stlm = _ida_allins.TMS320C54_stlm

TMS320C54_stm = _ida_allins.TMS320C54_stm

TMS320C54_cmps = _ida_allins.TMS320C54_cmps

TMS320C54_saccd = _ida_allins.TMS320C54_saccd

TMS320C54_srccd = _ida_allins.TMS320C54_srccd

TMS320C54_strcd = _ida_allins.TMS320C54_strcd

TMS320C54_st_ld = _ida_allins.TMS320C54_st_ld

TMS320C54_ld_mac = _ida_allins.TMS320C54_ld_mac

TMS320C54_ld_macr = _ida_allins.TMS320C54_ld_macr

TMS320C54_ld_mas = _ida_allins.TMS320C54_ld_mas

TMS320C54_ld_masr = _ida_allins.TMS320C54_ld_masr

TMS320C54_st_add = _ida_allins.TMS320C54_st_add

TMS320C54_st_sub = _ida_allins.TMS320C54_st_sub

TMS320C54_st_mac = _ida_allins.TMS320C54_st_mac

TMS320C54_st_macr = _ida_allins.TMS320C54_st_macr

TMS320C54_st_mas = _ida_allins.TMS320C54_st_mas

TMS320C54_st_masr = _ida_allins.TMS320C54_st_masr

TMS320C54_st_mpy = _ida_allins.TMS320C54_st_mpy

TMS320C54_mvdd = _ida_allins.TMS320C54_mvdd

TMS320C54_mvdk = _ida_allins.TMS320C54_mvdk

TMS320C54_mvdm = _ida_allins.TMS320C54_mvdm

TMS320C54_mvdp = _ida_allins.TMS320C54_mvdp

TMS320C54_mvkd = _ida_allins.TMS320C54_mvkd

TMS320C54_mvmd = _ida_allins.TMS320C54_mvmd

TMS320C54_mvmm = _ida_allins.TMS320C54_mvmm

TMS320C54_mvpd = _ida_allins.TMS320C54_mvpd

TMS320C54_portr = _ida_allins.TMS320C54_portr

TMS320C54_portw = _ida_allins.TMS320C54_portw

TMS320C54_reada = _ida_allins.TMS320C54_reada

TMS320C54_writa = _ida_allins.TMS320C54_writa

TMS320C54_last = _ida_allins.TMS320C54_last

TMS320C55_null = _ida_allins.TMS320C55_null

TMS320C55_abdst = _ida_allins.TMS320C55_abdst

TMS320C55_abs1 = _ida_allins.TMS320C55_abs1

TMS320C55_abs2 = _ida_allins.TMS320C55_abs2

TMS320C55_add1 = _ida_allins.TMS320C55_add1

TMS320C55_add2 = _ida_allins.TMS320C55_add2

TMS320C55_add3 = _ida_allins.TMS320C55_add3

TMS320C55_add4 = _ida_allins.TMS320C55_add4

TMS320C55_addv1 = _ida_allins.TMS320C55_addv1

TMS320C55_addv2 = _ida_allins.TMS320C55_addv2

TMS320C55_addrv1 = _ida_allins.TMS320C55_addrv1

TMS320C55_addrv2 = _ida_allins.TMS320C55_addrv2

TMS320C55_maxdiff = _ida_allins.TMS320C55_maxdiff

TMS320C55_dmaxdiff = _ida_allins.TMS320C55_dmaxdiff

TMS320C55_mindiff = _ida_allins.TMS320C55_mindiff

TMS320C55_dmindiff = _ida_allins.TMS320C55_dmindiff

TMS320C55_addsubcc4 = _ida_allins.TMS320C55_addsubcc4

TMS320C55_addsubcc5 = _ida_allins.TMS320C55_addsubcc5

TMS320C55_addsub2cc = _ida_allins.TMS320C55_addsub2cc

TMS320C55_sftcc = _ida_allins.TMS320C55_sftcc

TMS320C55_subc2 = _ida_allins.TMS320C55_subc2

TMS320C55_subc3 = _ida_allins.TMS320C55_subc3

TMS320C55_addsub = _ida_allins.TMS320C55_addsub

TMS320C55_subadd = _ida_allins.TMS320C55_subadd

TMS320C55_mpy_mpy = _ida_allins.TMS320C55_mpy_mpy

TMS320C55_mpy_mpyr = _ida_allins.TMS320C55_mpy_mpyr

TMS320C55_mpy_mpy40 = _ida_allins.TMS320C55_mpy_mpy40

TMS320C55_mpy_mpyr40 = _ida_allins.TMS320C55_mpy_mpyr40

TMS320C55_mac_mpy = _ida_allins.TMS320C55_mac_mpy

TMS320C55_macr_mpyr = _ida_allins.TMS320C55_macr_mpyr

TMS320C55_mac40_mpy40 = _ida_allins.TMS320C55_mac40_mpy40

TMS320C55_macr40_mpyr40 = _ida_allins.TMS320C55_macr40_mpyr40

TMS320C55_mas_mpy = _ida_allins.TMS320C55_mas_mpy

TMS320C55_masr_mpyr = _ida_allins.TMS320C55_masr_mpyr

TMS320C55_mas40_mpy40 = _ida_allins.TMS320C55_mas40_mpy40

TMS320C55_masr40_mpyr40 = _ida_allins.TMS320C55_masr40_mpyr40

TMS320C55_amar_mpy = _ida_allins.TMS320C55_amar_mpy

TMS320C55_amar_mpyr = _ida_allins.TMS320C55_amar_mpyr

TMS320C55_amar_mpy40 = _ida_allins.TMS320C55_amar_mpy40

TMS320C55_amar_mpyr40 = _ida_allins.TMS320C55_amar_mpyr40

TMS320C55_mac_mac = _ida_allins.TMS320C55_mac_mac

TMS320C55_macr_macr = _ida_allins.TMS320C55_macr_macr

TMS320C55_mac40_mac40 = _ida_allins.TMS320C55_mac40_mac40

TMS320C55_macr40_macr40 = _ida_allins.TMS320C55_macr40_macr40

TMS320C55_mas_mac = _ida_allins.TMS320C55_mas_mac

TMS320C55_masr_macr = _ida_allins.TMS320C55_masr_macr

TMS320C55_mas40_mac40 = _ida_allins.TMS320C55_mas40_mac40

TMS320C55_masr40_macr40 = _ida_allins.TMS320C55_masr40_macr40

TMS320C55_amar_mac = _ida_allins.TMS320C55_amar_mac

TMS320C55_amar_macr = _ida_allins.TMS320C55_amar_macr

TMS320C55_amar_mac40 = _ida_allins.TMS320C55_amar_mac40

TMS320C55_amar_macr40 = _ida_allins.TMS320C55_amar_macr40

TMS320C55_mas_mas = _ida_allins.TMS320C55_mas_mas

TMS320C55_masr_masr = _ida_allins.TMS320C55_masr_masr

TMS320C55_mas40_mas40 = _ida_allins.TMS320C55_mas40_mas40

TMS320C55_masr40_masr40 = _ida_allins.TMS320C55_masr40_masr40

TMS320C55_amar_mas = _ida_allins.TMS320C55_amar_mas

TMS320C55_amar_masr = _ida_allins.TMS320C55_amar_masr

TMS320C55_amar_mas40 = _ida_allins.TMS320C55_amar_mas40

TMS320C55_amar_masr40 = _ida_allins.TMS320C55_amar_masr40

TMS320C55_mpy_mac = _ida_allins.TMS320C55_mpy_mac

TMS320C55_mpyr_macr = _ida_allins.TMS320C55_mpyr_macr

TMS320C55_mpy40_mac40 = _ida_allins.TMS320C55_mpy40_mac40

TMS320C55_mpyr40_macr40 = _ida_allins.TMS320C55_mpyr40_macr40

TMS320C55_amar3 = _ida_allins.TMS320C55_amar3

TMS320C55_firsadd = _ida_allins.TMS320C55_firsadd

TMS320C55_firssub = _ida_allins.TMS320C55_firssub

TMS320C55_mpym_mov = _ida_allins.TMS320C55_mpym_mov

TMS320C55_mpymr_mov = _ida_allins.TMS320C55_mpymr_mov

TMS320C55_macm_mov = _ida_allins.TMS320C55_macm_mov

TMS320C55_macmr_mov = _ida_allins.TMS320C55_macmr_mov

TMS320C55_masm_mov = _ida_allins.TMS320C55_masm_mov

TMS320C55_masmr_mov = _ida_allins.TMS320C55_masmr_mov

TMS320C55_add_mov = _ida_allins.TMS320C55_add_mov

TMS320C55_sub_mov = _ida_allins.TMS320C55_sub_mov

TMS320C55_mov_mov = _ida_allins.TMS320C55_mov_mov

TMS320C55_mov_aadd = _ida_allins.TMS320C55_mov_aadd

TMS320C55_mov_add = _ida_allins.TMS320C55_mov_add

TMS320C55_amar_amar = _ida_allins.TMS320C55_amar_amar

TMS320C55_add_asub = _ida_allins.TMS320C55_add_asub

TMS320C55_btst_mov = _ida_allins.TMS320C55_btst_mov

TMS320C55_mov_asub = _ida_allins.TMS320C55_mov_asub

TMS320C55_lms = _ida_allins.TMS320C55_lms

TMS320C55_max1 = _ida_allins.TMS320C55_max1

TMS320C55_max2 = _ida_allins.TMS320C55_max2

TMS320C55_min1 = _ida_allins.TMS320C55_min1

TMS320C55_min2 = _ida_allins.TMS320C55_min2

TMS320C55_cmp = _ida_allins.TMS320C55_cmp

TMS320C55_cmpu = _ida_allins.TMS320C55_cmpu

TMS320C55_aadd = _ida_allins.TMS320C55_aadd

TMS320C55_asub = _ida_allins.TMS320C55_asub

TMS320C55_amov = _ida_allins.TMS320C55_amov

TMS320C55_amar1 = _ida_allins.TMS320C55_amar1

TMS320C55_sqr1 = _ida_allins.TMS320C55_sqr1

TMS320C55_sqr2 = _ida_allins.TMS320C55_sqr2

TMS320C55_sqrr1 = _ida_allins.TMS320C55_sqrr1

TMS320C55_sqrr2 = _ida_allins.TMS320C55_sqrr2

TMS320C55_mpy1 = _ida_allins.TMS320C55_mpy1

TMS320C55_mpy2 = _ida_allins.TMS320C55_mpy2

TMS320C55_mpy3 = _ida_allins.TMS320C55_mpy3

TMS320C55_mpyr1 = _ida_allins.TMS320C55_mpyr1

TMS320C55_mpyr2 = _ida_allins.TMS320C55_mpyr2

TMS320C55_mpyr3 = _ida_allins.TMS320C55_mpyr3

TMS320C55_mpyk2 = _ida_allins.TMS320C55_mpyk2

TMS320C55_mpyk3 = _ida_allins.TMS320C55_mpyk3

TMS320C55_mpykr2 = _ida_allins.TMS320C55_mpykr2

TMS320C55_mpykr3 = _ida_allins.TMS320C55_mpykr3

TMS320C55_mpym2 = _ida_allins.TMS320C55_mpym2

TMS320C55_mpym3 = _ida_allins.TMS320C55_mpym3

TMS320C55_mpymr2 = _ida_allins.TMS320C55_mpymr2

TMS320C55_mpymr3 = _ida_allins.TMS320C55_mpymr3

TMS320C55_mpym403 = _ida_allins.TMS320C55_mpym403

TMS320C55_mpymr403 = _ida_allins.TMS320C55_mpymr403

TMS320C55_mpymu3 = _ida_allins.TMS320C55_mpymu3

TMS320C55_mpymru3 = _ida_allins.TMS320C55_mpymru3

TMS320C55_sqrm = _ida_allins.TMS320C55_sqrm

TMS320C55_sqrmr = _ida_allins.TMS320C55_sqrmr

TMS320C55_mpymk = _ida_allins.TMS320C55_mpymk

TMS320C55_mpymkr = _ida_allins.TMS320C55_mpymkr

TMS320C55_sqa1 = _ida_allins.TMS320C55_sqa1

TMS320C55_sqa2 = _ida_allins.TMS320C55_sqa2

TMS320C55_sqar1 = _ida_allins.TMS320C55_sqar1

TMS320C55_sqar2 = _ida_allins.TMS320C55_sqar2

TMS320C55_mac3 = _ida_allins.TMS320C55_mac3

TMS320C55_mac4 = _ida_allins.TMS320C55_mac4

TMS320C55_macr3 = _ida_allins.TMS320C55_macr3

TMS320C55_macr4 = _ida_allins.TMS320C55_macr4

TMS320C55_mack3 = _ida_allins.TMS320C55_mack3

TMS320C55_mack4 = _ida_allins.TMS320C55_mack4

TMS320C55_mackr3 = _ida_allins.TMS320C55_mackr3

TMS320C55_mackr4 = _ida_allins.TMS320C55_mackr4

TMS320C55_macm2 = _ida_allins.TMS320C55_macm2

TMS320C55_macm3 = _ida_allins.TMS320C55_macm3

TMS320C55_macm4 = _ida_allins.TMS320C55_macm4

TMS320C55_macmr2 = _ida_allins.TMS320C55_macmr2

TMS320C55_macmr3 = _ida_allins.TMS320C55_macmr3

TMS320C55_macmr4 = _ida_allins.TMS320C55_macmr4

TMS320C55_macm403 = _ida_allins.TMS320C55_macm403

TMS320C55_macm404 = _ida_allins.TMS320C55_macm404

TMS320C55_macmr403 = _ida_allins.TMS320C55_macmr403

TMS320C55_macmr404 = _ida_allins.TMS320C55_macmr404

TMS320C55_macmz = _ida_allins.TMS320C55_macmz

TMS320C55_macmrz = _ida_allins.TMS320C55_macmrz

TMS320C55_sqam2 = _ida_allins.TMS320C55_sqam2

TMS320C55_sqam3 = _ida_allins.TMS320C55_sqam3

TMS320C55_sqamr2 = _ida_allins.TMS320C55_sqamr2

TMS320C55_sqamr3 = _ida_allins.TMS320C55_sqamr3

TMS320C55_macmk3 = _ida_allins.TMS320C55_macmk3

TMS320C55_macmk4 = _ida_allins.TMS320C55_macmk4

TMS320C55_macmkr3 = _ida_allins.TMS320C55_macmkr3

TMS320C55_macmkr4 = _ida_allins.TMS320C55_macmkr4

TMS320C55_sqs1 = _ida_allins.TMS320C55_sqs1

TMS320C55_sqs2 = _ida_allins.TMS320C55_sqs2

TMS320C55_sqsr1 = _ida_allins.TMS320C55_sqsr1

TMS320C55_sqsr2 = _ida_allins.TMS320C55_sqsr2

TMS320C55_mas2 = _ida_allins.TMS320C55_mas2

TMS320C55_mas3 = _ida_allins.TMS320C55_mas3

TMS320C55_masr2 = _ida_allins.TMS320C55_masr2

TMS320C55_masr3 = _ida_allins.TMS320C55_masr3

TMS320C55_masm2 = _ida_allins.TMS320C55_masm2

TMS320C55_masm3 = _ida_allins.TMS320C55_masm3

TMS320C55_masm4 = _ida_allins.TMS320C55_masm4

TMS320C55_masmr2 = _ida_allins.TMS320C55_masmr2

TMS320C55_masmr3 = _ida_allins.TMS320C55_masmr3

TMS320C55_masmr4 = _ida_allins.TMS320C55_masmr4

TMS320C55_masm403 = _ida_allins.TMS320C55_masm403

TMS320C55_masm404 = _ida_allins.TMS320C55_masm404

TMS320C55_masmr403 = _ida_allins.TMS320C55_masmr403

TMS320C55_masmr404 = _ida_allins.TMS320C55_masmr404

TMS320C55_sqsm2 = _ida_allins.TMS320C55_sqsm2

TMS320C55_sqsm3 = _ida_allins.TMS320C55_sqsm3

TMS320C55_sqsmr2 = _ida_allins.TMS320C55_sqsmr2

TMS320C55_sqsmr3 = _ida_allins.TMS320C55_sqsmr3

TMS320C55_neg1 = _ida_allins.TMS320C55_neg1

TMS320C55_neg2 = _ida_allins.TMS320C55_neg2

TMS320C55_mant_nexp = _ida_allins.TMS320C55_mant_nexp

TMS320C55_exp = _ida_allins.TMS320C55_exp

TMS320C55_cmpand = _ida_allins.TMS320C55_cmpand

TMS320C55_cmpandu = _ida_allins.TMS320C55_cmpandu

TMS320C55_cmpor = _ida_allins.TMS320C55_cmpor

TMS320C55_cmporu = _ida_allins.TMS320C55_cmporu

TMS320C55_round1 = _ida_allins.TMS320C55_round1

TMS320C55_round2 = _ida_allins.TMS320C55_round2

TMS320C55_sat1 = _ida_allins.TMS320C55_sat1

TMS320C55_sat2 = _ida_allins.TMS320C55_sat2

TMS320C55_satr1 = _ida_allins.TMS320C55_satr1

TMS320C55_satr2 = _ida_allins.TMS320C55_satr2

TMS320C55_sfts2 = _ida_allins.TMS320C55_sfts2

TMS320C55_sfts3 = _ida_allins.TMS320C55_sfts3

TMS320C55_sftsc2 = _ida_allins.TMS320C55_sftsc2

TMS320C55_sftsc3 = _ida_allins.TMS320C55_sftsc3

TMS320C55_sqdst = _ida_allins.TMS320C55_sqdst

TMS320C55_sub1 = _ida_allins.TMS320C55_sub1

TMS320C55_sub2 = _ida_allins.TMS320C55_sub2

TMS320C55_sub3 = _ida_allins.TMS320C55_sub3

TMS320C55_sub4 = _ida_allins.TMS320C55_sub4

TMS320C55_band = _ida_allins.TMS320C55_band

TMS320C55_bfxpa = _ida_allins.TMS320C55_bfxpa

TMS320C55_bfxtr = _ida_allins.TMS320C55_bfxtr

TMS320C55_btst = _ida_allins.TMS320C55_btst

TMS320C55_bnot = _ida_allins.TMS320C55_bnot

TMS320C55_bclr2 = _ida_allins.TMS320C55_bclr2

TMS320C55_bset2 = _ida_allins.TMS320C55_bset2

TMS320C55_btstset = _ida_allins.TMS320C55_btstset

TMS320C55_btstclr = _ida_allins.TMS320C55_btstclr

TMS320C55_btstnot = _ida_allins.TMS320C55_btstnot

TMS320C55_btstp = _ida_allins.TMS320C55_btstp

TMS320C55_bclr1 = _ida_allins.TMS320C55_bclr1

TMS320C55_bset1 = _ida_allins.TMS320C55_bset1

TMS320C55_amar2 = _ida_allins.TMS320C55_amar2

TMS320C55_popboth = _ida_allins.TMS320C55_popboth

TMS320C55_pshboth = _ida_allins.TMS320C55_pshboth

TMS320C55_bcnt = _ida_allins.TMS320C55_bcnt

TMS320C55_not1 = _ida_allins.TMS320C55_not1

TMS320C55_not2 = _ida_allins.TMS320C55_not2

TMS320C55_and1 = _ida_allins.TMS320C55_and1

TMS320C55_and2 = _ida_allins.TMS320C55_and2

TMS320C55_and3 = _ida_allins.TMS320C55_and3

TMS320C55_or1 = _ida_allins.TMS320C55_or1

TMS320C55_or2 = _ida_allins.TMS320C55_or2

TMS320C55_or3 = _ida_allins.TMS320C55_or3

TMS320C55_xor1 = _ida_allins.TMS320C55_xor1

TMS320C55_xor2 = _ida_allins.TMS320C55_xor2

TMS320C55_xor3 = _ida_allins.TMS320C55_xor3

TMS320C55_sftl2 = _ida_allins.TMS320C55_sftl2

TMS320C55_sftl3 = _ida_allins.TMS320C55_sftl3

TMS320C55_rol = _ida_allins.TMS320C55_rol

TMS320C55_ror = _ida_allins.TMS320C55_ror

TMS320C55_swap = _ida_allins.TMS320C55_swap

TMS320C55_swapp = _ida_allins.TMS320C55_swapp

TMS320C55_swap4 = _ida_allins.TMS320C55_swap4

TMS320C55_mov2 = _ida_allins.TMS320C55_mov2

TMS320C55_mov3 = _ida_allins.TMS320C55_mov3

TMS320C55_mov402 = _ida_allins.TMS320C55_mov402

TMS320C55_delay = _ida_allins.TMS320C55_delay

TMS320C55_pop1 = _ida_allins.TMS320C55_pop1

TMS320C55_pop2 = _ida_allins.TMS320C55_pop2

TMS320C55_psh1 = _ida_allins.TMS320C55_psh1

TMS320C55_psh2 = _ida_allins.TMS320C55_psh2

TMS320C55_bcc = _ida_allins.TMS320C55_bcc

TMS320C55_bccu = _ida_allins.TMS320C55_bccu

TMS320C55_b = _ida_allins.TMS320C55_b

TMS320C55_callcc = _ida_allins.TMS320C55_callcc

TMS320C55_call = _ida_allins.TMS320C55_call

TMS320C55_xcc = _ida_allins.TMS320C55_xcc

TMS320C55_xccpart = _ida_allins.TMS320C55_xccpart

TMS320C55_idle = _ida_allins.TMS320C55_idle

TMS320C55_nop = _ida_allins.TMS320C55_nop

TMS320C55_nop_16 = _ida_allins.TMS320C55_nop_16

TMS320C55_rptblocal = _ida_allins.TMS320C55_rptblocal

TMS320C55_rptb = _ida_allins.TMS320C55_rptb

TMS320C55_rptcc = _ida_allins.TMS320C55_rptcc

TMS320C55_rpt = _ida_allins.TMS320C55_rpt

TMS320C55_rptadd = _ida_allins.TMS320C55_rptadd

TMS320C55_rptsub = _ida_allins.TMS320C55_rptsub

TMS320C55_retcc = _ida_allins.TMS320C55_retcc

TMS320C55_ret = _ida_allins.TMS320C55_ret

TMS320C55_reti = _ida_allins.TMS320C55_reti

TMS320C55_intr = _ida_allins.TMS320C55_intr

TMS320C55_reset = _ida_allins.TMS320C55_reset

TMS320C55_trap = _ida_allins.TMS320C55_trap

TMS320C55_last = _ida_allins.TMS320C55_last

TRIMEDIA_null = _ida_allins.TRIMEDIA_null

TRIMEDIA_igtri = _ida_allins.TRIMEDIA_igtri

TRIMEDIA_igeqi = _ida_allins.TRIMEDIA_igeqi

TRIMEDIA_ilesi = _ida_allins.TRIMEDIA_ilesi

TRIMEDIA_ineqi = _ida_allins.TRIMEDIA_ineqi

TRIMEDIA_ieqli = _ida_allins.TRIMEDIA_ieqli

TRIMEDIA_iaddi = _ida_allins.TRIMEDIA_iaddi

TRIMEDIA_ild16d = _ida_allins.TRIMEDIA_ild16d

TRIMEDIA_ld32d = _ida_allins.TRIMEDIA_ld32d

TRIMEDIA_uld8d = _ida_allins.TRIMEDIA_uld8d

TRIMEDIA_lsri = _ida_allins.TRIMEDIA_lsri

TRIMEDIA_asri = _ida_allins.TRIMEDIA_asri

TRIMEDIA_asli = _ida_allins.TRIMEDIA_asli

TRIMEDIA_iadd = _ida_allins.TRIMEDIA_iadd

TRIMEDIA_isub = _ida_allins.TRIMEDIA_isub

TRIMEDIA_igeq = _ida_allins.TRIMEDIA_igeq

TRIMEDIA_igtr = _ida_allins.TRIMEDIA_igtr

TRIMEDIA_bitand = _ida_allins.TRIMEDIA_bitand

TRIMEDIA_bitor = _ida_allins.TRIMEDIA_bitor

TRIMEDIA_asr = _ida_allins.TRIMEDIA_asr

TRIMEDIA_asl = _ida_allins.TRIMEDIA_asl

TRIMEDIA_ifloat = _ida_allins.TRIMEDIA_ifloat

TRIMEDIA_ifixrz = _ida_allins.TRIMEDIA_ifixrz

TRIMEDIA_fadd = _ida_allins.TRIMEDIA_fadd

TRIMEDIA_imin = _ida_allins.TRIMEDIA_imin

TRIMEDIA_imax = _ida_allins.TRIMEDIA_imax

TRIMEDIA_iavgonep = _ida_allins.TRIMEDIA_iavgonep

TRIMEDIA_ume8uu = _ida_allins.TRIMEDIA_ume8uu

TRIMEDIA_imul = _ida_allins.TRIMEDIA_imul

TRIMEDIA_fmul = _ida_allins.TRIMEDIA_fmul

TRIMEDIA_h_st8d = _ida_allins.TRIMEDIA_h_st8d

TRIMEDIA_h_st16d = _ida_allins.TRIMEDIA_h_st16d

TRIMEDIA_h_st32d = _ida_allins.TRIMEDIA_h_st32d

TRIMEDIA_isubi = _ida_allins.TRIMEDIA_isubi

TRIMEDIA_ugtr = _ida_allins.TRIMEDIA_ugtr

TRIMEDIA_ugtri = _ida_allins.TRIMEDIA_ugtri

TRIMEDIA_ugeq = _ida_allins.TRIMEDIA_ugeq

TRIMEDIA_ugeqi = _ida_allins.TRIMEDIA_ugeqi

TRIMEDIA_ieql = _ida_allins.TRIMEDIA_ieql

TRIMEDIA_ueqli = _ida_allins.TRIMEDIA_ueqli

TRIMEDIA_ineq = _ida_allins.TRIMEDIA_ineq

TRIMEDIA_uneqi = _ida_allins.TRIMEDIA_uneqi

TRIMEDIA_ulesi = _ida_allins.TRIMEDIA_ulesi

TRIMEDIA_ileqi = _ida_allins.TRIMEDIA_ileqi

TRIMEDIA_uleqi = _ida_allins.TRIMEDIA_uleqi

TRIMEDIA_h_iabs = _ida_allins.TRIMEDIA_h_iabs

TRIMEDIA_carry = _ida_allins.TRIMEDIA_carry

TRIMEDIA_izero = _ida_allins.TRIMEDIA_izero

TRIMEDIA_inonzero = _ida_allins.TRIMEDIA_inonzero

TRIMEDIA_bitxor = _ida_allins.TRIMEDIA_bitxor

TRIMEDIA_bitandinv = _ida_allins.TRIMEDIA_bitandinv

TRIMEDIA_bitinv = _ida_allins.TRIMEDIA_bitinv

TRIMEDIA_sex16 = _ida_allins.TRIMEDIA_sex16

TRIMEDIA_packbytes = _ida_allins.TRIMEDIA_packbytes

TRIMEDIA_pack16lsb = _ida_allins.TRIMEDIA_pack16lsb

TRIMEDIA_pack16msb = _ida_allins.TRIMEDIA_pack16msb

TRIMEDIA_ubytesel = _ida_allins.TRIMEDIA_ubytesel

TRIMEDIA_ibytesel = _ida_allins.TRIMEDIA_ibytesel

TRIMEDIA_mergelsb = _ida_allins.TRIMEDIA_mergelsb

TRIMEDIA_mergemsb = _ida_allins.TRIMEDIA_mergemsb

TRIMEDIA_ume8ii = _ida_allins.TRIMEDIA_ume8ii

TRIMEDIA_h_dspiabs = _ida_allins.TRIMEDIA_h_dspiabs

TRIMEDIA_dspiadd = _ida_allins.TRIMEDIA_dspiadd

TRIMEDIA_dspuadd = _ida_allins.TRIMEDIA_dspuadd

TRIMEDIA_dspisub = _ida_allins.TRIMEDIA_dspisub

TRIMEDIA_dspusub = _ida_allins.TRIMEDIA_dspusub

TRIMEDIA_dspidualadd = _ida_allins.TRIMEDIA_dspidualadd

TRIMEDIA_dspidualsub = _ida_allins.TRIMEDIA_dspidualsub

TRIMEDIA_h_dspidualabs = _ida_allins.TRIMEDIA_h_dspidualabs

TRIMEDIA_quadavg = _ida_allins.TRIMEDIA_quadavg

TRIMEDIA_iclipi = _ida_allins.TRIMEDIA_iclipi

TRIMEDIA_uclipi = _ida_allins.TRIMEDIA_uclipi

TRIMEDIA_uclipu = _ida_allins.TRIMEDIA_uclipu

TRIMEDIA_iflip = _ida_allins.TRIMEDIA_iflip

TRIMEDIA_dspuquadaddui = _ida_allins.TRIMEDIA_dspuquadaddui

TRIMEDIA_quadumin = _ida_allins.TRIMEDIA_quadumin

TRIMEDIA_quadumax = _ida_allins.TRIMEDIA_quadumax

TRIMEDIA_dualiclipi = _ida_allins.TRIMEDIA_dualiclipi

TRIMEDIA_dualuclipi = _ida_allins.TRIMEDIA_dualuclipi

TRIMEDIA_quadumulmsb = _ida_allins.TRIMEDIA_quadumulmsb

TRIMEDIA_ufir8uu = _ida_allins.TRIMEDIA_ufir8uu

TRIMEDIA_ifir8ui = _ida_allins.TRIMEDIA_ifir8ui

TRIMEDIA_ifir8ii = _ida_allins.TRIMEDIA_ifir8ii

TRIMEDIA_ifir16 = _ida_allins.TRIMEDIA_ifir16

TRIMEDIA_ufir16 = _ida_allins.TRIMEDIA_ufir16

TRIMEDIA_dspidualmul = _ida_allins.TRIMEDIA_dspidualmul

TRIMEDIA_lsr = _ida_allins.TRIMEDIA_lsr

TRIMEDIA_rol = _ida_allins.TRIMEDIA_rol

TRIMEDIA_roli = _ida_allins.TRIMEDIA_roli

TRIMEDIA_funshift1 = _ida_allins.TRIMEDIA_funshift1

TRIMEDIA_funshift2 = _ida_allins.TRIMEDIA_funshift2

TRIMEDIA_funshift3 = _ida_allins.TRIMEDIA_funshift3

TRIMEDIA_dualasr = _ida_allins.TRIMEDIA_dualasr

TRIMEDIA_mergedual16lsb = _ida_allins.TRIMEDIA_mergedual16lsb

TRIMEDIA_fdiv = _ida_allins.TRIMEDIA_fdiv

TRIMEDIA_fdivflags = _ida_allins.TRIMEDIA_fdivflags

TRIMEDIA_fsqrt = _ida_allins.TRIMEDIA_fsqrt

TRIMEDIA_fsqrtflags = _ida_allins.TRIMEDIA_fsqrtflags

TRIMEDIA_faddflags = _ida_allins.TRIMEDIA_faddflags

TRIMEDIA_fsub = _ida_allins.TRIMEDIA_fsub

TRIMEDIA_fsubflags = _ida_allins.TRIMEDIA_fsubflags

TRIMEDIA_fabsval = _ida_allins.TRIMEDIA_fabsval

TRIMEDIA_fabsvalflags = _ida_allins.TRIMEDIA_fabsvalflags

TRIMEDIA_ifloatrz = _ida_allins.TRIMEDIA_ifloatrz

TRIMEDIA_ifloatrzflags = _ida_allins.TRIMEDIA_ifloatrzflags

TRIMEDIA_ufloatrz = _ida_allins.TRIMEDIA_ufloatrz

TRIMEDIA_ufloatrzflags = _ida_allins.TRIMEDIA_ufloatrzflags

TRIMEDIA_ifixieee = _ida_allins.TRIMEDIA_ifixieee

TRIMEDIA_ifixieeeflags = _ida_allins.TRIMEDIA_ifixieeeflags

TRIMEDIA_ufixieee = _ida_allins.TRIMEDIA_ufixieee

TRIMEDIA_ufixieeeflags = _ida_allins.TRIMEDIA_ufixieeeflags

TRIMEDIA_ufixrz = _ida_allins.TRIMEDIA_ufixrz

TRIMEDIA_ufixrzflags = _ida_allins.TRIMEDIA_ufixrzflags

TRIMEDIA_ufloat = _ida_allins.TRIMEDIA_ufloat

TRIMEDIA_ufloatflags = _ida_allins.TRIMEDIA_ufloatflags

TRIMEDIA_ifixrzflags = _ida_allins.TRIMEDIA_ifixrzflags

TRIMEDIA_ifloatflags = _ida_allins.TRIMEDIA_ifloatflags

TRIMEDIA_umul = _ida_allins.TRIMEDIA_umul

TRIMEDIA_imulm = _ida_allins.TRIMEDIA_imulm

TRIMEDIA_umulm = _ida_allins.TRIMEDIA_umulm

TRIMEDIA_dspimul = _ida_allins.TRIMEDIA_dspimul

TRIMEDIA_dspumul = _ida_allins.TRIMEDIA_dspumul

TRIMEDIA_fmulflags = _ida_allins.TRIMEDIA_fmulflags

TRIMEDIA_fgtr = _ida_allins.TRIMEDIA_fgtr

TRIMEDIA_fgtrflags = _ida_allins.TRIMEDIA_fgtrflags

TRIMEDIA_fgeq = _ida_allins.TRIMEDIA_fgeq

TRIMEDIA_fgeqflags = _ida_allins.TRIMEDIA_fgeqflags

TRIMEDIA_feql = _ida_allins.TRIMEDIA_feql

TRIMEDIA_feqlflags = _ida_allins.TRIMEDIA_feqlflags

TRIMEDIA_fneq = _ida_allins.TRIMEDIA_fneq

TRIMEDIA_fneqflags = _ida_allins.TRIMEDIA_fneqflags

TRIMEDIA_fsign = _ida_allins.TRIMEDIA_fsign

TRIMEDIA_fsignflags = _ida_allins.TRIMEDIA_fsignflags

TRIMEDIA_cycles = _ida_allins.TRIMEDIA_cycles

TRIMEDIA_hicycles = _ida_allins.TRIMEDIA_hicycles

TRIMEDIA_readdpc = _ida_allins.TRIMEDIA_readdpc

TRIMEDIA_readspc = _ida_allins.TRIMEDIA_readspc

TRIMEDIA_readpcsw = _ida_allins.TRIMEDIA_readpcsw

TRIMEDIA_writespc = _ida_allins.TRIMEDIA_writespc

TRIMEDIA_writedpc = _ida_allins.TRIMEDIA_writedpc

TRIMEDIA_writepcsw = _ida_allins.TRIMEDIA_writepcsw

TRIMEDIA_curcycles = _ida_allins.TRIMEDIA_curcycles

TRIMEDIA_jmpt = _ida_allins.TRIMEDIA_jmpt

TRIMEDIA_ijmpt = _ida_allins.TRIMEDIA_ijmpt

TRIMEDIA_jmpi = _ida_allins.TRIMEDIA_jmpi

TRIMEDIA_ijmpi = _ida_allins.TRIMEDIA_ijmpi

TRIMEDIA_jmpf = _ida_allins.TRIMEDIA_jmpf

TRIMEDIA_ijmpf = _ida_allins.TRIMEDIA_ijmpf

TRIMEDIA_iclr = _ida_allins.TRIMEDIA_iclr

TRIMEDIA_uimm = _ida_allins.TRIMEDIA_uimm

TRIMEDIA_ild8d = _ida_allins.TRIMEDIA_ild8d

TRIMEDIA_ild8r = _ida_allins.TRIMEDIA_ild8r

TRIMEDIA_uld8r = _ida_allins.TRIMEDIA_uld8r

TRIMEDIA_ild16r = _ida_allins.TRIMEDIA_ild16r

TRIMEDIA_ild16x = _ida_allins.TRIMEDIA_ild16x

TRIMEDIA_uld16d = _ida_allins.TRIMEDIA_uld16d

TRIMEDIA_uld16r = _ida_allins.TRIMEDIA_uld16r

TRIMEDIA_uld16x = _ida_allins.TRIMEDIA_uld16x

TRIMEDIA_ld32r = _ida_allins.TRIMEDIA_ld32r

TRIMEDIA_ld32x = _ida_allins.TRIMEDIA_ld32x

TRIMEDIA_rdtag = _ida_allins.TRIMEDIA_rdtag

TRIMEDIA_rdstatus = _ida_allins.TRIMEDIA_rdstatus

TRIMEDIA_dcb = _ida_allins.TRIMEDIA_dcb

TRIMEDIA_dinvalid = _ida_allins.TRIMEDIA_dinvalid

TRIMEDIA_prefd = _ida_allins.TRIMEDIA_prefd

TRIMEDIA_prefr = _ida_allins.TRIMEDIA_prefr

TRIMEDIA_pref16x = _ida_allins.TRIMEDIA_pref16x

TRIMEDIA_pref32x = _ida_allins.TRIMEDIA_pref32x

TRIMEDIA_allocd = _ida_allins.TRIMEDIA_allocd

TRIMEDIA_allocr = _ida_allins.TRIMEDIA_allocr

TRIMEDIA_allocx = _ida_allins.TRIMEDIA_allocx

TRIMEDIA_nop = _ida_allins.TRIMEDIA_nop

TRIMEDIA_alloc = _ida_allins.TRIMEDIA_alloc

TRIMEDIA_dspiabs = _ida_allins.TRIMEDIA_dspiabs

TRIMEDIA_dspidualabs = _ida_allins.TRIMEDIA_dspidualabs

TRIMEDIA_iabs = _ida_allins.TRIMEDIA_iabs

TRIMEDIA_ild16 = _ida_allins.TRIMEDIA_ild16

TRIMEDIA_ild8 = _ida_allins.TRIMEDIA_ild8

TRIMEDIA_ineg = _ida_allins.TRIMEDIA_ineg

TRIMEDIA_ld32 = _ida_allins.TRIMEDIA_ld32

TRIMEDIA_pref = _ida_allins.TRIMEDIA_pref

TRIMEDIA_sex8 = _ida_allins.TRIMEDIA_sex8

TRIMEDIA_st16 = _ida_allins.TRIMEDIA_st16

TRIMEDIA_st16d = _ida_allins.TRIMEDIA_st16d

TRIMEDIA_st32 = _ida_allins.TRIMEDIA_st32

TRIMEDIA_st32d = _ida_allins.TRIMEDIA_st32d

TRIMEDIA_st8 = _ida_allins.TRIMEDIA_st8

TRIMEDIA_st8d = _ida_allins.TRIMEDIA_st8d

TRIMEDIA_uld16 = _ida_allins.TRIMEDIA_uld16

TRIMEDIA_uld8 = _ida_allins.TRIMEDIA_uld8

TRIMEDIA_zex16 = _ida_allins.TRIMEDIA_zex16

TRIMEDIA_zex8 = _ida_allins.TRIMEDIA_zex8

TRIMEDIA_ident = _ida_allins.TRIMEDIA_ident

TRIMEDIA_iles = _ida_allins.TRIMEDIA_iles

TRIMEDIA_ileq = _ida_allins.TRIMEDIA_ileq

TRIMEDIA_ules = _ida_allins.TRIMEDIA_ules

TRIMEDIA_uleq = _ida_allins.TRIMEDIA_uleq

TRIMEDIA_fles = _ida_allins.TRIMEDIA_fles

TRIMEDIA_fleq = _ida_allins.TRIMEDIA_fleq

TRIMEDIA_ueql = _ida_allins.TRIMEDIA_ueql

TRIMEDIA_uneq = _ida_allins.TRIMEDIA_uneq

TRIMEDIA_flesflags = _ida_allins.TRIMEDIA_flesflags

TRIMEDIA_fleqflags = _ida_allins.TRIMEDIA_fleqflags

TRIMEDIA_borrow = _ida_allins.TRIMEDIA_borrow

TRIMEDIA_umin = _ida_allins.TRIMEDIA_umin

TRIMEDIA_lsl = _ida_allins.TRIMEDIA_lsl

TRIMEDIA_lsli = _ida_allins.TRIMEDIA_lsli

TRIMEDIA_last = _ida_allins.TRIMEDIA_last

NEC_78K_0_null = _ida_allins.NEC_78K_0_null

NEC_78K_0_mov = _ida_allins.NEC_78K_0_mov

NEC_78K_0_xch = _ida_allins.NEC_78K_0_xch

NEC_78K_0_movw = _ida_allins.NEC_78K_0_movw

NEC_78K_0_xchw = _ida_allins.NEC_78K_0_xchw

NEC_78K_0_add = _ida_allins.NEC_78K_0_add

NEC_78K_0_addc = _ida_allins.NEC_78K_0_addc

NEC_78K_0_sub = _ida_allins.NEC_78K_0_sub

NEC_78K_0_subc = _ida_allins.NEC_78K_0_subc

NEC_78K_0_and = _ida_allins.NEC_78K_0_and

NEC_78K_0_or = _ida_allins.NEC_78K_0_or

NEC_78K_0_xor = _ida_allins.NEC_78K_0_xor

NEC_78K_0_cmp = _ida_allins.NEC_78K_0_cmp

NEC_78K_0_addw = _ida_allins.NEC_78K_0_addw

NEC_78K_0_subw = _ida_allins.NEC_78K_0_subw

NEC_78K_0_cmpw = _ida_allins.NEC_78K_0_cmpw

NEC_78K_0_mulu = _ida_allins.NEC_78K_0_mulu

NEC_78K_0_divuw = _ida_allins.NEC_78K_0_divuw

NEC_78K_0_inc = _ida_allins.NEC_78K_0_inc

NEC_78K_0_dec = _ida_allins.NEC_78K_0_dec

NEC_78K_0_incw = _ida_allins.NEC_78K_0_incw

NEC_78K_0_decw = _ida_allins.NEC_78K_0_decw

NEC_78K_0_ror = _ida_allins.NEC_78K_0_ror

NEC_78K_0_rol = _ida_allins.NEC_78K_0_rol

NEC_78K_0_rorc = _ida_allins.NEC_78K_0_rorc

NEC_78K_0_rolc = _ida_allins.NEC_78K_0_rolc

NEC_78K_0_ror4 = _ida_allins.NEC_78K_0_ror4

NEC_78K_0_rol4 = _ida_allins.NEC_78K_0_rol4

NEC_78K_0_adjba = _ida_allins.NEC_78K_0_adjba

NEC_78K_0_adjbs = _ida_allins.NEC_78K_0_adjbs

NEC_78K_0_mov1 = _ida_allins.NEC_78K_0_mov1

NEC_78K_0_and1 = _ida_allins.NEC_78K_0_and1

NEC_78K_0_or1 = _ida_allins.NEC_78K_0_or1

NEC_78K_0_xor1 = _ida_allins.NEC_78K_0_xor1

NEC_78K_0_set1 = _ida_allins.NEC_78K_0_set1

NEC_78K_0_clr1 = _ida_allins.NEC_78K_0_clr1

NEC_78K_0_not1 = _ida_allins.NEC_78K_0_not1

NEC_78K_0_call = _ida_allins.NEC_78K_0_call

NEC_78K_0_callf = _ida_allins.NEC_78K_0_callf

NEC_78K_0_callt = _ida_allins.NEC_78K_0_callt

NEC_78K_0_brk = _ida_allins.NEC_78K_0_brk

NEC_78K_0_ret = _ida_allins.NEC_78K_0_ret

NEC_78K_0_retb = _ida_allins.NEC_78K_0_retb

NEC_78K_0_reti = _ida_allins.NEC_78K_0_reti

NEC_78K_0_push = _ida_allins.NEC_78K_0_push

NEC_78K_0_pop = _ida_allins.NEC_78K_0_pop

NEC_78K_0_br = _ida_allins.NEC_78K_0_br

NEC_78K_0_bc = _ida_allins.NEC_78K_0_bc

NEC_78K_0_bnc = _ida_allins.NEC_78K_0_bnc

NEC_78K_0_bz = _ida_allins.NEC_78K_0_bz

NEC_78K_0_bnz = _ida_allins.NEC_78K_0_bnz

NEC_78K_0_bt = _ida_allins.NEC_78K_0_bt

NEC_78K_0_bf = _ida_allins.NEC_78K_0_bf

NEC_78K_0_btclr = _ida_allins.NEC_78K_0_btclr

NEC_78K_0_dbnz = _ida_allins.NEC_78K_0_dbnz

NEC_78K_0_sel = _ida_allins.NEC_78K_0_sel

NEC_78K_0_nop = _ida_allins.NEC_78K_0_nop

NEC_78K_0_EI = _ida_allins.NEC_78K_0_EI

NEC_78K_0_DI = _ida_allins.NEC_78K_0_DI

NEC_78K_0_HALT = _ida_allins.NEC_78K_0_HALT

NEC_78K_0_STOP = _ida_allins.NEC_78K_0_STOP

NEC_78K_0_last = _ida_allins.NEC_78K_0_last

NEC_78K_0S_null = _ida_allins.NEC_78K_0S_null

NEC_78K_0S_cmp = _ida_allins.NEC_78K_0S_cmp

NEC_78K_0S_xor = _ida_allins.NEC_78K_0S_xor

NEC_78K_0S_and = _ida_allins.NEC_78K_0S_and

NEC_78K_0S_or = _ida_allins.NEC_78K_0S_or

NEC_78K_0S_add = _ida_allins.NEC_78K_0S_add

NEC_78K_0S_sub = _ida_allins.NEC_78K_0S_sub

NEC_78K_0S_addc = _ida_allins.NEC_78K_0S_addc

NEC_78K_0S_subc = _ida_allins.NEC_78K_0S_subc

NEC_78K_0S_subw = _ida_allins.NEC_78K_0S_subw

NEC_78K_0S_addw = _ida_allins.NEC_78K_0S_addw

NEC_78K_0S_cmpw = _ida_allins.NEC_78K_0S_cmpw

NEC_78K_0S_inc = _ida_allins.NEC_78K_0S_inc

NEC_78K_0S_dec = _ida_allins.NEC_78K_0S_dec

NEC_78K_0S_incw = _ida_allins.NEC_78K_0S_incw

NEC_78K_0S_decw = _ida_allins.NEC_78K_0S_decw

NEC_78K_0S_ror = _ida_allins.NEC_78K_0S_ror

NEC_78K_0S_rol = _ida_allins.NEC_78K_0S_rol

NEC_78K_0S_rorc = _ida_allins.NEC_78K_0S_rorc

NEC_78K_0S_rolc = _ida_allins.NEC_78K_0S_rolc

NEC_78K_0S_call = _ida_allins.NEC_78K_0S_call

NEC_78K_0S_callt = _ida_allins.NEC_78K_0S_callt

NEC_78K_0S_ret = _ida_allins.NEC_78K_0S_ret

NEC_78K_0S_reti = _ida_allins.NEC_78K_0S_reti

NEC_78K_0S_mov = _ida_allins.NEC_78K_0S_mov

NEC_78K_0S_xch = _ida_allins.NEC_78K_0S_xch

NEC_78K_0S_xchw = _ida_allins.NEC_78K_0S_xchw

NEC_78K_0S_set1 = _ida_allins.NEC_78K_0S_set1

NEC_78K_0S_clr1 = _ida_allins.NEC_78K_0S_clr1

NEC_78K_0S_not1 = _ida_allins.NEC_78K_0S_not1

NEC_78K_0S_push = _ida_allins.NEC_78K_0S_push

NEC_78K_0S_pop = _ida_allins.NEC_78K_0S_pop

NEC_78K_0S_movw = _ida_allins.NEC_78K_0S_movw

NEC_78K_0S_br = _ida_allins.NEC_78K_0S_br

NEC_78K_0S_bc = _ida_allins.NEC_78K_0S_bc

NEC_78K_0S_bnc = _ida_allins.NEC_78K_0S_bnc

NEC_78K_0S_bz = _ida_allins.NEC_78K_0S_bz

NEC_78K_0S_bnz = _ida_allins.NEC_78K_0S_bnz

NEC_78K_0S_bt = _ida_allins.NEC_78K_0S_bt

NEC_78K_0S_bf = _ida_allins.NEC_78K_0S_bf

NEC_78K_0S_dbnz = _ida_allins.NEC_78K_0S_dbnz

NEC_78K_0S_nop = _ida_allins.NEC_78K_0S_nop

NEC_78K_0S_EI = _ida_allins.NEC_78K_0S_EI

NEC_78K_0S_DI = _ida_allins.NEC_78K_0S_DI

NEC_78K_0S_HALT = _ida_allins.NEC_78K_0S_HALT

NEC_78K_0S_STOP = _ida_allins.NEC_78K_0S_STOP

NEC_78K_0S_last = _ida_allins.NEC_78K_0S_last

M16C_null = _ida_allins.M16C_null

M16C_abs = _ida_allins.M16C_abs

M16C_adc = _ida_allins.M16C_adc

M16C_adcf = _ida_allins.M16C_adcf

M16C_add = _ida_allins.M16C_add

M16C_adjnz = _ida_allins.M16C_adjnz

M16C_and = _ida_allins.M16C_and

M16C_band = _ida_allins.M16C_band

M16C_bclr = _ida_allins.M16C_bclr

M16C_bmcnd = _ida_allins.M16C_bmcnd

M16C_bmgeu = _ida_allins.M16C_bmgeu

M16C_bmgtu = _ida_allins.M16C_bmgtu

M16C_bmeq = _ida_allins.M16C_bmeq

M16C_bmn = _ida_allins.M16C_bmn

M16C_bmle = _ida_allins.M16C_bmle

M16C_bmo = _ida_allins.M16C_bmo

M16C_bmge = _ida_allins.M16C_bmge

M16C_bmltu = _ida_allins.M16C_bmltu

M16C_bmleu = _ida_allins.M16C_bmleu

M16C_bmne = _ida_allins.M16C_bmne

M16C_bmpz = _ida_allins.M16C_bmpz

M16C_bmgt = _ida_allins.M16C_bmgt

M16C_bmno = _ida_allins.M16C_bmno

M16C_bmlt = _ida_allins.M16C_bmlt

M16C_bnand = _ida_allins.M16C_bnand

M16C_bnor = _ida_allins.M16C_bnor

M16C_bnot = _ida_allins.M16C_bnot

M16C_bntst = _ida_allins.M16C_bntst

M16C_bnxor = _ida_allins.M16C_bnxor

M16C_bor = _ida_allins.M16C_bor

M16C_brk = _ida_allins.M16C_brk

M16C_bset = _ida_allins.M16C_bset

M16C_btst = _ida_allins.M16C_btst

M16C_btstc = _ida_allins.M16C_btstc

M16C_btsts = _ida_allins.M16C_btsts

M16C_bxor = _ida_allins.M16C_bxor

M16C_cmp = _ida_allins.M16C_cmp

M16C_dadc = _ida_allins.M16C_dadc

M16C_dadd = _ida_allins.M16C_dadd

M16C_dec = _ida_allins.M16C_dec

M16C_div = _ida_allins.M16C_div

M16C_divu = _ida_allins.M16C_divu

M16C_divx = _ida_allins.M16C_divx

M16C_dsbb = _ida_allins.M16C_dsbb

M16C_dsub = _ida_allins.M16C_dsub

M16C_enter = _ida_allins.M16C_enter

M16C_exitd = _ida_allins.M16C_exitd

M16C_exts = _ida_allins.M16C_exts

M16C_fclr = _ida_allins.M16C_fclr

M16C_fset = _ida_allins.M16C_fset

M16C_inc = _ida_allins.M16C_inc

M16C_int = _ida_allins.M16C_int

M16C_into = _ida_allins.M16C_into

M16C_jcnd = _ida_allins.M16C_jcnd

M16C_jgeu = _ida_allins.M16C_jgeu

M16C_jgtu = _ida_allins.M16C_jgtu

M16C_jeq = _ida_allins.M16C_jeq

M16C_jn = _ida_allins.M16C_jn

M16C_jle = _ida_allins.M16C_jle

M16C_jo = _ida_allins.M16C_jo

M16C_jge = _ida_allins.M16C_jge

M16C_jltu = _ida_allins.M16C_jltu

M16C_jleu = _ida_allins.M16C_jleu

M16C_jne = _ida_allins.M16C_jne

M16C_jpz = _ida_allins.M16C_jpz

M16C_jgt = _ida_allins.M16C_jgt

M16C_jno = _ida_allins.M16C_jno

M16C_jlt = _ida_allins.M16C_jlt

M16C_jmp = _ida_allins.M16C_jmp

M16C_jmpi = _ida_allins.M16C_jmpi

M16C_jmps = _ida_allins.M16C_jmps

M16C_jsr = _ida_allins.M16C_jsr

M16C_jsri = _ida_allins.M16C_jsri

M16C_jsrs = _ida_allins.M16C_jsrs

M16C_ldc = _ida_allins.M16C_ldc

M16C_ldctx = _ida_allins.M16C_ldctx

M16C_lde = _ida_allins.M16C_lde

M16C_ldintb = _ida_allins.M16C_ldintb

M16C_ldipl = _ida_allins.M16C_ldipl

M16C_mov = _ida_allins.M16C_mov

M16C_mova = _ida_allins.M16C_mova

M16C_movhh = _ida_allins.M16C_movhh

M16C_movhl = _ida_allins.M16C_movhl

M16C_movlh = _ida_allins.M16C_movlh

M16C_movll = _ida_allins.M16C_movll

M16C_mul = _ida_allins.M16C_mul

M16C_mulu = _ida_allins.M16C_mulu

M16C_neg = _ida_allins.M16C_neg

M16C_nop = _ida_allins.M16C_nop

M16C_not = _ida_allins.M16C_not

M16C_or = _ida_allins.M16C_or

M16C_pop = _ida_allins.M16C_pop

M16C_popc = _ida_allins.M16C_popc

M16C_popm = _ida_allins.M16C_popm

M16C_push = _ida_allins.M16C_push

M16C_pusha = _ida_allins.M16C_pusha

M16C_pushc = _ida_allins.M16C_pushc

M16C_pushm = _ida_allins.M16C_pushm

M16C_reit = _ida_allins.M16C_reit

M16C_rmpa = _ida_allins.M16C_rmpa

M16C_rolc = _ida_allins.M16C_rolc

M16C_rorc = _ida_allins.M16C_rorc

M16C_rot = _ida_allins.M16C_rot

M16C_rts = _ida_allins.M16C_rts

M16C_sbb = _ida_allins.M16C_sbb

M16C_sbjnz = _ida_allins.M16C_sbjnz

M16C_sha = _ida_allins.M16C_sha

M16C_shl = _ida_allins.M16C_shl

M16C_smovb = _ida_allins.M16C_smovb

M16C_smovf = _ida_allins.M16C_smovf

M16C_sstr = _ida_allins.M16C_sstr

M16C_stc = _ida_allins.M16C_stc

M16C_stctx = _ida_allins.M16C_stctx

M16C_ste = _ida_allins.M16C_ste

M16C_stnz = _ida_allins.M16C_stnz

M16C_stz = _ida_allins.M16C_stz

M16C_stzx = _ida_allins.M16C_stzx

M16C_sub = _ida_allins.M16C_sub

M16C_tst = _ida_allins.M16C_tst

M16C_und = _ida_allins.M16C_und

M16C_wait = _ida_allins.M16C_wait

M16C_xchg = _ida_allins.M16C_xchg

M16C_xor = _ida_allins.M16C_xor

M16C_addx = _ida_allins.M16C_addx

M16C_bitindex = _ida_allins.M16C_bitindex

M16C_brk2 = _ida_allins.M16C_brk2

M16C_clip = _ida_allins.M16C_clip

M16C_cmpx = _ida_allins.M16C_cmpx

M16C_extz = _ida_allins.M16C_extz

M16C_freit = _ida_allins.M16C_freit

M16C_indexb = _ida_allins.M16C_indexb

M16C_indexbd = _ida_allins.M16C_indexbd

M16C_indexbs = _ida_allins.M16C_indexbs

M16C_indexl = _ida_allins.M16C_indexl

M16C_indexld = _ida_allins.M16C_indexld

M16C_indexls = _ida_allins.M16C_indexls

M16C_indexw = _ida_allins.M16C_indexw

M16C_indexwd = _ida_allins.M16C_indexwd

M16C_indexws = _ida_allins.M16C_indexws

M16C_max = _ida_allins.M16C_max

M16C_min = _ida_allins.M16C_min

M16C_movx = _ida_allins.M16C_movx

M16C_mulex = _ida_allins.M16C_mulex

M16C_sccnd = _ida_allins.M16C_sccnd

M16C_scgeu = _ida_allins.M16C_scgeu

M16C_scgtu = _ida_allins.M16C_scgtu

M16C_sceq = _ida_allins.M16C_sceq

M16C_scn = _ida_allins.M16C_scn

M16C_scle = _ida_allins.M16C_scle

M16C_sco = _ida_allins.M16C_sco

M16C_scge = _ida_allins.M16C_scge

M16C_scltu = _ida_allins.M16C_scltu

M16C_scleu = _ida_allins.M16C_scleu

M16C_scne = _ida_allins.M16C_scne

M16C_scpz = _ida_allins.M16C_scpz

M16C_scgt = _ida_allins.M16C_scgt

M16C_scno = _ida_allins.M16C_scno

M16C_sclt = _ida_allins.M16C_sclt

M16C_scmpu = _ida_allins.M16C_scmpu

M16C_sin = _ida_allins.M16C_sin

M16C_smovu = _ida_allins.M16C_smovu

M16C_sout = _ida_allins.M16C_sout

M16C_subx = _ida_allins.M16C_subx

M16C_shanc = _ida_allins.M16C_shanc

M16C_shlnc = _ida_allins.M16C_shlnc

M16C_addf = _ida_allins.M16C_addf

M16C_adsf = _ida_allins.M16C_adsf

M16C_cmpf = _ida_allins.M16C_cmpf

M16C_cnvif = _ida_allins.M16C_cnvif

M16C_divf = _ida_allins.M16C_divf

M16C_ediv = _ida_allins.M16C_ediv

M16C_edivu = _ida_allins.M16C_edivu

M16C_edivx = _ida_allins.M16C_edivx

M16C_emul = _ida_allins.M16C_emul

M16C_emulu = _ida_allins.M16C_emulu

M16C_exiti = _ida_allins.M16C_exiti

M16C_index1 = _ida_allins.M16C_index1

M16C_index2 = _ida_allins.M16C_index2

M16C_mulf = _ida_allins.M16C_mulf

M16C_mulx = _ida_allins.M16C_mulx

M16C_round = _ida_allins.M16C_round

M16C_stop = _ida_allins.M16C_stop

M16C_subf = _ida_allins.M16C_subf

M16C_suntil = _ida_allins.M16C_suntil

M16C_swhile = _ida_allins.M16C_swhile

M16C_last = _ida_allins.M16C_last

m32r_null = _ida_allins.m32r_null

m32r_add = _ida_allins.m32r_add

m32r_add3 = _ida_allins.m32r_add3

m32r_addi = _ida_allins.m32r_addi

m32r_addv = _ida_allins.m32r_addv

m32r_addv3 = _ida_allins.m32r_addv3

m32r_addx = _ida_allins.m32r_addx

m32r_and = _ida_allins.m32r_and

m32r_and3 = _ida_allins.m32r_and3

m32r_bc = _ida_allins.m32r_bc

m32r_beq = _ida_allins.m32r_beq

m32r_beqz = _ida_allins.m32r_beqz

m32r_bgez = _ida_allins.m32r_bgez

m32r_bgtz = _ida_allins.m32r_bgtz

m32r_bl = _ida_allins.m32r_bl

m32r_blez = _ida_allins.m32r_blez

m32r_bltz = _ida_allins.m32r_bltz

m32r_bnc = _ida_allins.m32r_bnc

m32r_bne = _ida_allins.m32r_bne

m32r_bnez = _ida_allins.m32r_bnez

m32r_bra = _ida_allins.m32r_bra

m32r_cmp = _ida_allins.m32r_cmp

m32r_cmpi = _ida_allins.m32r_cmpi

m32r_cmpu = _ida_allins.m32r_cmpu

m32r_cmpui = _ida_allins.m32r_cmpui

m32r_div = _ida_allins.m32r_div

m32r_divu = _ida_allins.m32r_divu

m32r_jl = _ida_allins.m32r_jl

m32r_jmp = _ida_allins.m32r_jmp

m32r_ld = _ida_allins.m32r_ld

m32r_ld24 = _ida_allins.m32r_ld24

m32r_ldb = _ida_allins.m32r_ldb

m32r_ldh = _ida_allins.m32r_ldh

m32r_ldi = _ida_allins.m32r_ldi

m32r_ldub = _ida_allins.m32r_ldub

m32r_lduh = _ida_allins.m32r_lduh

m32r_lock = _ida_allins.m32r_lock

m32r_machi = _ida_allins.m32r_machi

m32r_maclo = _ida_allins.m32r_maclo

m32r_macwhi = _ida_allins.m32r_macwhi

m32r_macwlo = _ida_allins.m32r_macwlo

m32r_mul = _ida_allins.m32r_mul

m32r_mulhi = _ida_allins.m32r_mulhi

m32r_mullo = _ida_allins.m32r_mullo

m32r_mulwhi = _ida_allins.m32r_mulwhi

m32r_mulwlo = _ida_allins.m32r_mulwlo

m32r_mv = _ida_allins.m32r_mv

m32r_mvfachi = _ida_allins.m32r_mvfachi

m32r_mvfaclo = _ida_allins.m32r_mvfaclo

m32r_mvfacmi = _ida_allins.m32r_mvfacmi

m32r_mvfc = _ida_allins.m32r_mvfc

m32r_mvtachi = _ida_allins.m32r_mvtachi

m32r_mvtaclo = _ida_allins.m32r_mvtaclo

m32r_mvtc = _ida_allins.m32r_mvtc

m32r_neg = _ida_allins.m32r_neg

m32r_nop = _ida_allins.m32r_nop

m32r_not = _ida_allins.m32r_not

m32r_or = _ida_allins.m32r_or

m32r_or3 = _ida_allins.m32r_or3

m32r_push = _ida_allins.m32r_push

m32r_pop = _ida_allins.m32r_pop

m32r_rac = _ida_allins.m32r_rac

m32r_rach = _ida_allins.m32r_rach

m32r_rem = _ida_allins.m32r_rem

m32r_remu = _ida_allins.m32r_remu

m32r_rte = _ida_allins.m32r_rte

m32r_seth = _ida_allins.m32r_seth

m32r_sll = _ida_allins.m32r_sll

m32r_sll3 = _ida_allins.m32r_sll3

m32r_slli = _ida_allins.m32r_slli

m32r_sra = _ida_allins.m32r_sra

m32r_sra3 = _ida_allins.m32r_sra3

m32r_srai = _ida_allins.m32r_srai

m32r_srl = _ida_allins.m32r_srl

m32r_srl3 = _ida_allins.m32r_srl3

m32r_srli = _ida_allins.m32r_srli

m32r_st = _ida_allins.m32r_st

m32r_stb = _ida_allins.m32r_stb

m32r_sth = _ida_allins.m32r_sth

m32r_sub = _ida_allins.m32r_sub

m32r_subv = _ida_allins.m32r_subv

m32r_subx = _ida_allins.m32r_subx

m32r_trap = _ida_allins.m32r_trap

m32r_unlock = _ida_allins.m32r_unlock

m32r_xor = _ida_allins.m32r_xor

m32r_xor3 = _ida_allins.m32r_xor3

m32rx_bcl = _ida_allins.m32rx_bcl

m32rx_bncl = _ida_allins.m32rx_bncl

m32rx_cmpeq = _ida_allins.m32rx_cmpeq

m32rx_cmpz = _ida_allins.m32rx_cmpz

m32rx_divh = _ida_allins.m32rx_divh

m32rx_jc = _ida_allins.m32rx_jc

m32rx_jnc = _ida_allins.m32rx_jnc

m32rx_machi = _ida_allins.m32rx_machi

m32rx_maclo = _ida_allins.m32rx_maclo

m32rx_macwhi = _ida_allins.m32rx_macwhi

m32rx_macwlo = _ida_allins.m32rx_macwlo

m32rx_mulhi = _ida_allins.m32rx_mulhi

m32rx_mullo = _ida_allins.m32rx_mullo

m32rx_mulwhi = _ida_allins.m32rx_mulwhi

m32rx_mulwlo = _ida_allins.m32rx_mulwlo

m32rx_mvfachi = _ida_allins.m32rx_mvfachi

m32rx_mvfaclo = _ida_allins.m32rx_mvfaclo

m32rx_mvfacmi = _ida_allins.m32rx_mvfacmi

m32rx_mvtachi = _ida_allins.m32rx_mvtachi

m32rx_mvtaclo = _ida_allins.m32rx_mvtaclo

m32rx_rac = _ida_allins.m32rx_rac

m32rx_rach = _ida_allins.m32rx_rach

m32rx_satb = _ida_allins.m32rx_satb

m32rx_sath = _ida_allins.m32rx_sath

m32rx_sat = _ida_allins.m32rx_sat

m32rx_pcmpbz = _ida_allins.m32rx_pcmpbz

m32rx_sadd = _ida_allins.m32rx_sadd

m32rx_macwu1 = _ida_allins.m32rx_macwu1

m32rx_msblo = _ida_allins.m32rx_msblo

m32rx_mulwu1 = _ida_allins.m32rx_mulwu1

m32rx_maclh1 = _ida_allins.m32rx_maclh1

m32rx_sc = _ida_allins.m32rx_sc

m32rx_snc = _ida_allins.m32rx_snc

m32r_fadd = _ida_allins.m32r_fadd

m32r_fsub = _ida_allins.m32r_fsub

m32r_fmul = _ida_allins.m32r_fmul

m32r_fdiv = _ida_allins.m32r_fdiv

m32r_fmadd = _ida_allins.m32r_fmadd

m32r_fmsub = _ida_allins.m32r_fmsub

m32r_itof = _ida_allins.m32r_itof

m32r_utof = _ida_allins.m32r_utof

m32r_ftoi = _ida_allins.m32r_ftoi

m32r_ftos = _ida_allins.m32r_ftos

m32r_fcmp = _ida_allins.m32r_fcmp

m32r_fcmpe = _ida_allins.m32r_fcmpe

m32r_bset = _ida_allins.m32r_bset

m32r_bclr = _ida_allins.m32r_bclr

m32r_btst = _ida_allins.m32r_btst

m32r_setpsw = _ida_allins.m32r_setpsw

m32r_clrpsw = _ida_allins.m32r_clrpsw

m32r_last = _ida_allins.m32r_last

m740_null = _ida_allins.m740_null

m740_adc = _ida_allins.m740_adc

m740_and = _ida_allins.m740_and

m740_asl = _ida_allins.m740_asl

m740_bbc = _ida_allins.m740_bbc

m740_bbs = _ida_allins.m740_bbs

m740_bcc = _ida_allins.m740_bcc

m740_bcs = _ida_allins.m740_bcs

m740_beq = _ida_allins.m740_beq

m740_bit = _ida_allins.m740_bit

m740_bmi = _ida_allins.m740_bmi

m740_bne = _ida_allins.m740_bne

m740_bpl = _ida_allins.m740_bpl

m740_bra = _ida_allins.m740_bra

m740_brk = _ida_allins.m740_brk

m740_bvc = _ida_allins.m740_bvc

m740_bvs = _ida_allins.m740_bvs

m740_clb = _ida_allins.m740_clb

m740_clc = _ida_allins.m740_clc

m740_cld = _ida_allins.m740_cld

m740_cli = _ida_allins.m740_cli

m740_clt = _ida_allins.m740_clt

m740_clv = _ida_allins.m740_clv

m740_cmp = _ida_allins.m740_cmp

m740_com = _ida_allins.m740_com

m740_cpx = _ida_allins.m740_cpx

m740_cpy = _ida_allins.m740_cpy

m740_dec = _ida_allins.m740_dec

m740_dex = _ida_allins.m740_dex

m740_dey = _ida_allins.m740_dey

m740_div = _ida_allins.m740_div

m740_eor = _ida_allins.m740_eor

m740_inc = _ida_allins.m740_inc

m740_inx = _ida_allins.m740_inx

m740_iny = _ida_allins.m740_iny

m740_jmp = _ida_allins.m740_jmp

m740_jsr = _ida_allins.m740_jsr

m740_lda = _ida_allins.m740_lda

m740_ldm = _ida_allins.m740_ldm

m740_ldx = _ida_allins.m740_ldx

m740_ldy = _ida_allins.m740_ldy

m740_lsr = _ida_allins.m740_lsr

m740_mul = _ida_allins.m740_mul

m740_nop = _ida_allins.m740_nop

m740_ora = _ida_allins.m740_ora

m740_pha = _ida_allins.m740_pha

m740_php = _ida_allins.m740_php

m740_pla = _ida_allins.m740_pla

m740_plp = _ida_allins.m740_plp

m740_rol = _ida_allins.m740_rol

m740_ror = _ida_allins.m740_ror

m740_rrf = _ida_allins.m740_rrf

m740_rti = _ida_allins.m740_rti

m740_rts = _ida_allins.m740_rts

m740_sbc = _ida_allins.m740_sbc

m740_seb = _ida_allins.m740_seb

m740_sec = _ida_allins.m740_sec

m740_sed = _ida_allins.m740_sed

m740_sei = _ida_allins.m740_sei

m740_set = _ida_allins.m740_set

m740_sta = _ida_allins.m740_sta

m740_stp = _ida_allins.m740_stp

m740_stx = _ida_allins.m740_stx

m740_sty = _ida_allins.m740_sty

m740_tax = _ida_allins.m740_tax

m740_tay = _ida_allins.m740_tay

m740_tst = _ida_allins.m740_tst

m740_tsx = _ida_allins.m740_tsx

m740_txa = _ida_allins.m740_txa

m740_txs = _ida_allins.m740_txs

m740_tya = _ida_allins.m740_tya

m740_wit = _ida_allins.m740_wit

m740_last = _ida_allins.m740_last

m7700_null = _ida_allins.m7700_null

m7700_adc = _ida_allins.m7700_adc

m7700_and = _ida_allins.m7700_and

m7700_asl = _ida_allins.m7700_asl

m7700_bbc = _ida_allins.m7700_bbc

m7700_bbs = _ida_allins.m7700_bbs

m7700_bcc = _ida_allins.m7700_bcc

m7700_bcs = _ida_allins.m7700_bcs

m7700_beq = _ida_allins.m7700_beq

m7700_bmi = _ida_allins.m7700_bmi

m7700_bne = _ida_allins.m7700_bne

m7700_bpl = _ida_allins.m7700_bpl

m7700_bra = _ida_allins.m7700_bra

m7700_brk = _ida_allins.m7700_brk

m7700_bvc = _ida_allins.m7700_bvc

m7700_bvs = _ida_allins.m7700_bvs

m7700_clb = _ida_allins.m7700_clb

m7700_clc = _ida_allins.m7700_clc

m7700_cli = _ida_allins.m7700_cli

m7700_clm = _ida_allins.m7700_clm

m7700_clp = _ida_allins.m7700_clp

m7700_clv = _ida_allins.m7700_clv

m7700_cmp = _ida_allins.m7700_cmp

m7700_cpx = _ida_allins.m7700_cpx

m7700_cpy = _ida_allins.m7700_cpy

m7700_dec = _ida_allins.m7700_dec

m7700_dex = _ida_allins.m7700_dex

m7700_dey = _ida_allins.m7700_dey

m7700_div = _ida_allins.m7700_div

m7700_eor = _ida_allins.m7700_eor

m7700_inc = _ida_allins.m7700_inc

m7700_inx = _ida_allins.m7700_inx

m7700_iny = _ida_allins.m7700_iny

m7700_jmp = _ida_allins.m7700_jmp

m7700_jsr = _ida_allins.m7700_jsr

m7700_lda = _ida_allins.m7700_lda

m7700_ldm = _ida_allins.m7700_ldm

m7700_ldt = _ida_allins.m7700_ldt

m7700_ldx = _ida_allins.m7700_ldx

m7700_ldy = _ida_allins.m7700_ldy

m7700_lsr = _ida_allins.m7700_lsr

m7700_mpy = _ida_allins.m7700_mpy

m7700_mvn = _ida_allins.m7700_mvn

m7700_mvp = _ida_allins.m7700_mvp

m7700_nop = _ida_allins.m7700_nop

m7700_ora = _ida_allins.m7700_ora

m7700_pea = _ida_allins.m7700_pea

m7700_pei = _ida_allins.m7700_pei

m7700_per = _ida_allins.m7700_per

m7700_pha = _ida_allins.m7700_pha

m7700_phb = _ida_allins.m7700_phb

m7700_phd = _ida_allins.m7700_phd

m7700_phg = _ida_allins.m7700_phg

m7700_php = _ida_allins.m7700_php

m7700_pht = _ida_allins.m7700_pht

m7700_phx = _ida_allins.m7700_phx

m7700_phy = _ida_allins.m7700_phy

m7700_pla = _ida_allins.m7700_pla

m7700_plb = _ida_allins.m7700_plb

m7700_pld = _ida_allins.m7700_pld

m7700_plp = _ida_allins.m7700_plp

m7700_plt = _ida_allins.m7700_plt

m7700_plx = _ida_allins.m7700_plx

m7700_ply = _ida_allins.m7700_ply

m7700_psh = _ida_allins.m7700_psh

m7700_pul = _ida_allins.m7700_pul

m7700_rla = _ida_allins.m7700_rla

m7700_rol = _ida_allins.m7700_rol

m7700_ror = _ida_allins.m7700_ror

m7700_rti = _ida_allins.m7700_rti

m7700_rtl = _ida_allins.m7700_rtl

m7700_rts = _ida_allins.m7700_rts

m7700_sbc = _ida_allins.m7700_sbc

m7700_seb = _ida_allins.m7700_seb

m7700_sec = _ida_allins.m7700_sec

m7700_sei = _ida_allins.m7700_sei

m7700_sem = _ida_allins.m7700_sem

m7700_sep = _ida_allins.m7700_sep

m7700_sta = _ida_allins.m7700_sta

m7700_stp = _ida_allins.m7700_stp

m7700_stx = _ida_allins.m7700_stx

m7700_sty = _ida_allins.m7700_sty

m7700_tad = _ida_allins.m7700_tad

m7700_tas = _ida_allins.m7700_tas

m7700_tax = _ida_allins.m7700_tax

m7700_tay = _ida_allins.m7700_tay

m7700_tbd = _ida_allins.m7700_tbd

m7700_tbs = _ida_allins.m7700_tbs

m7700_tbx = _ida_allins.m7700_tbx

m7700_tby = _ida_allins.m7700_tby

m7700_tda = _ida_allins.m7700_tda

m7700_tdb = _ida_allins.m7700_tdb

m7700_tsa = _ida_allins.m7700_tsa

m7700_tsb = _ida_allins.m7700_tsb

m7700_tsx = _ida_allins.m7700_tsx

m7700_txa = _ida_allins.m7700_txa

m7700_txb = _ida_allins.m7700_txb

m7700_txs = _ida_allins.m7700_txs

m7700_txy = _ida_allins.m7700_txy

m7700_tya = _ida_allins.m7700_tya

m7700_tyb = _ida_allins.m7700_tyb

m7700_tyx = _ida_allins.m7700_tyx

m7700_wit = _ida_allins.m7700_wit

m7700_xab = _ida_allins.m7700_xab

m7750_asr = _ida_allins.m7750_asr

m7750_divs = _ida_allins.m7750_divs

m7750_exts = _ida_allins.m7750_exts

m7750_extz = _ida_allins.m7750_extz

m7750_mpys = _ida_allins.m7750_mpys

m7700_last = _ida_allins.m7700_last

m7900_null = _ida_allins.m7900_null

m7900_abs = _ida_allins.m7900_abs

m7900_absd = _ida_allins.m7900_absd

m7900_adc = _ida_allins.m7900_adc

m7900_adcb = _ida_allins.m7900_adcb

m7900_adcd = _ida_allins.m7900_adcd

m7900_add = _ida_allins.m7900_add

m7900_addb = _ida_allins.m7900_addb

m7900_addd = _ida_allins.m7900_addd

m7900_addm = _ida_allins.m7900_addm

m7900_addmb = _ida_allins.m7900_addmb

m7900_addmd = _ida_allins.m7900_addmd

m7900_adds = _ida_allins.m7900_adds

m7900_addx = _ida_allins.m7900_addx

m7900_addy = _ida_allins.m7900_addy

m7900_and = _ida_allins.m7900_and

m7900_andb = _ida_allins.m7900_andb

m7900_andm = _ida_allins.m7900_andm

m7900_andmb = _ida_allins.m7900_andmb

m7900_andmd = _ida_allins.m7900_andmd

m7900_asl = _ida_allins.m7900_asl

m7900_asln = _ida_allins.m7900_asln

m7900_asldn = _ida_allins.m7900_asldn

m7900_asr = _ida_allins.m7900_asr

m7900_asrn = _ida_allins.m7900_asrn

m7900_asrdn = _ida_allins.m7900_asrdn

m7900_bbc = _ida_allins.m7900_bbc

m7900_bbcb = _ida_allins.m7900_bbcb

m7900_bbs = _ida_allins.m7900_bbs

m7900_bbsb = _ida_allins.m7900_bbsb

m7900_bcc = _ida_allins.m7900_bcc

m7900_bcs = _ida_allins.m7900_bcs

m7900_beq = _ida_allins.m7900_beq

m7900_bge = _ida_allins.m7900_bge

m7900_bgt = _ida_allins.m7900_bgt

m7900_bgtu = _ida_allins.m7900_bgtu

m7900_ble = _ida_allins.m7900_ble

m7900_bleu = _ida_allins.m7900_bleu

m7900_blt = _ida_allins.m7900_blt

m7900_bmi = _ida_allins.m7900_bmi

m7900_bne = _ida_allins.m7900_bne

m7900_bpl = _ida_allins.m7900_bpl

m7900_bra = _ida_allins.m7900_bra

m7900_bral = _ida_allins.m7900_bral

m7900_brk = _ida_allins.m7900_brk

m7900_bsc = _ida_allins.m7900_bsc

m7900_bsr = _ida_allins.m7900_bsr

m7900_bss = _ida_allins.m7900_bss

m7900_bvc = _ida_allins.m7900_bvc

m7900_bvs = _ida_allins.m7900_bvs

m7900_cbeq = _ida_allins.m7900_cbeq

m7900_cbeqb = _ida_allins.m7900_cbeqb

m7900_cbne = _ida_allins.m7900_cbne

m7900_cbneb = _ida_allins.m7900_cbneb

m7900_clc = _ida_allins.m7900_clc

m7900_cli = _ida_allins.m7900_cli

m7900_clm = _ida_allins.m7900_clm

m7900_clp = _ida_allins.m7900_clp

m7900_clr = _ida_allins.m7900_clr

m7900_clrb = _ida_allins.m7900_clrb

m7900_clrm = _ida_allins.m7900_clrm

m7900_clrmb = _ida_allins.m7900_clrmb

m7900_clrx = _ida_allins.m7900_clrx

m7900_clry = _ida_allins.m7900_clry

m7900_clv = _ida_allins.m7900_clv

m7900_cmp = _ida_allins.m7900_cmp

m7900_cmpb = _ida_allins.m7900_cmpb

m7900_cmpd = _ida_allins.m7900_cmpd

m7900_cmpm = _ida_allins.m7900_cmpm

m7900_cmpmb = _ida_allins.m7900_cmpmb

m7900_cmpmd = _ida_allins.m7900_cmpmd

m7900_cpx = _ida_allins.m7900_cpx

m7900_cpy = _ida_allins.m7900_cpy

m7900_debne = _ida_allins.m7900_debne

m7900_dec = _ida_allins.m7900_dec

m7900_dex = _ida_allins.m7900_dex

m7900_dey = _ida_allins.m7900_dey

m7900_div = _ida_allins.m7900_div

m7900_divs = _ida_allins.m7900_divs

m7900_dxbne = _ida_allins.m7900_dxbne

m7900_dybne = _ida_allins.m7900_dybne

m7900_eor = _ida_allins.m7900_eor

m7900_eorb = _ida_allins.m7900_eorb

m7900_eorm = _ida_allins.m7900_eorm

m7900_eormb = _ida_allins.m7900_eormb

m7900_eormd = _ida_allins.m7900_eormd

m7900_exts = _ida_allins.m7900_exts

m7900_extsd = _ida_allins.m7900_extsd

m7900_extz = _ida_allins.m7900_extz

m7900_extzd = _ida_allins.m7900_extzd

m7900_inc = _ida_allins.m7900_inc

m7900_inx = _ida_allins.m7900_inx

m7900_iny = _ida_allins.m7900_iny

m7900_jmp = _ida_allins.m7900_jmp

m7900_jmpl = _ida_allins.m7900_jmpl

m7900_jsr = _ida_allins.m7900_jsr

m7900_jsrl = _ida_allins.m7900_jsrl

m7900_lda = _ida_allins.m7900_lda

m7900_ldab = _ida_allins.m7900_ldab

m7900_ldad = _ida_allins.m7900_ldad

m7900_lddn = _ida_allins.m7900_lddn

m7900_ldt = _ida_allins.m7900_ldt

m7900_ldx = _ida_allins.m7900_ldx

m7900_ldxb = _ida_allins.m7900_ldxb

m7900_ldy = _ida_allins.m7900_ldy

m7900_ldyb = _ida_allins.m7900_ldyb

m7900_lsr = _ida_allins.m7900_lsr

m7900_lsrn = _ida_allins.m7900_lsrn

m7900_lsrdn = _ida_allins.m7900_lsrdn

m7900_movm = _ida_allins.m7900_movm

m7900_movmb = _ida_allins.m7900_movmb

m7900_movr = _ida_allins.m7900_movr

m7900_movrb = _ida_allins.m7900_movrb

m7900_mpy = _ida_allins.m7900_mpy

m7900_mpys = _ida_allins.m7900_mpys

m7900_mvn = _ida_allins.m7900_mvn

m7900_mvp = _ida_allins.m7900_mvp

m7900_neg = _ida_allins.m7900_neg

m7900_negd = _ida_allins.m7900_negd

m7900_nop = _ida_allins.m7900_nop

m7900_ora = _ida_allins.m7900_ora

m7900_orab = _ida_allins.m7900_orab

m7900_oram = _ida_allins.m7900_oram

m7900_oramb = _ida_allins.m7900_oramb

m7900_oramd = _ida_allins.m7900_oramd

m7900_pea = _ida_allins.m7900_pea

m7900_pei = _ida_allins.m7900_pei

m7900_per = _ida_allins.m7900_per

m7900_pha = _ida_allins.m7900_pha

m7900_phb = _ida_allins.m7900_phb

m7900_phd = _ida_allins.m7900_phd

m7900_phdn = _ida_allins.m7900_phdn

m7900_phg = _ida_allins.m7900_phg

m7900_phldn = _ida_allins.m7900_phldn

m7900_php = _ida_allins.m7900_php

m7900_pht = _ida_allins.m7900_pht

m7900_phx = _ida_allins.m7900_phx

m7900_phy = _ida_allins.m7900_phy

m7900_pla = _ida_allins.m7900_pla

m7900_plb = _ida_allins.m7900_plb

m7900_pld = _ida_allins.m7900_pld

m7900_pldn = _ida_allins.m7900_pldn

m7900_plp = _ida_allins.m7900_plp

m7900_plt = _ida_allins.m7900_plt

m7900_plx = _ida_allins.m7900_plx

m7900_ply = _ida_allins.m7900_ply

m7900_psh = _ida_allins.m7900_psh

m7900_pul = _ida_allins.m7900_pul

m7900_rla = _ida_allins.m7900_rla

m7900_rmpa = _ida_allins.m7900_rmpa

m7900_rol = _ida_allins.m7900_rol

m7900_roln = _ida_allins.m7900_roln

m7900_roldn = _ida_allins.m7900_roldn

m7900_ror = _ida_allins.m7900_ror

m7900_rorn = _ida_allins.m7900_rorn

m7900_rordn = _ida_allins.m7900_rordn

m7900_rti = _ida_allins.m7900_rti

m7900_rtl = _ida_allins.m7900_rtl

m7900_rtld = _ida_allins.m7900_rtld

m7900_rts = _ida_allins.m7900_rts

m7900_rtsdn = _ida_allins.m7900_rtsdn

m7900_sbc = _ida_allins.m7900_sbc

m7900_sbcb = _ida_allins.m7900_sbcb

m7900_sbcd = _ida_allins.m7900_sbcd

m7900_sec = _ida_allins.m7900_sec

m7900_sei = _ida_allins.m7900_sei

m7900_sem = _ida_allins.m7900_sem

m7900_sep = _ida_allins.m7900_sep

m7900_sta = _ida_allins.m7900_sta

m7900_stab = _ida_allins.m7900_stab

m7900_stad = _ida_allins.m7900_stad

m7900_stp = _ida_allins.m7900_stp

m7900_stx = _ida_allins.m7900_stx

m7900_sty = _ida_allins.m7900_sty

m7900_sub = _ida_allins.m7900_sub

m7900_subb = _ida_allins.m7900_subb

m7900_subd = _ida_allins.m7900_subd

m7900_subm = _ida_allins.m7900_subm

m7900_submb = _ida_allins.m7900_submb

m7900_submd = _ida_allins.m7900_submd

m7900_subs = _ida_allins.m7900_subs

m7900_subx = _ida_allins.m7900_subx

m7900_suby = _ida_allins.m7900_suby

m7900_tadn = _ida_allins.m7900_tadn

m7900_tas = _ida_allins.m7900_tas

m7900_tax = _ida_allins.m7900_tax

m7900_tay = _ida_allins.m7900_tay

m7900_tbdn = _ida_allins.m7900_tbdn

m7900_tbs = _ida_allins.m7900_tbs

m7900_tbx = _ida_allins.m7900_tbx

m7900_tby = _ida_allins.m7900_tby

m7900_tdan = _ida_allins.m7900_tdan

m7900_tdbn = _ida_allins.m7900_tdbn

m7900_tds = _ida_allins.m7900_tds

m7900_tsa = _ida_allins.m7900_tsa

m7900_tsb = _ida_allins.m7900_tsb

m7900_tsd = _ida_allins.m7900_tsd

m7900_tsx = _ida_allins.m7900_tsx

m7900_txa = _ida_allins.m7900_txa

m7900_txb = _ida_allins.m7900_txb

m7900_txs = _ida_allins.m7900_txs

m7900_txy = _ida_allins.m7900_txy

m7900_tya = _ida_allins.m7900_tya

m7900_tyb = _ida_allins.m7900_tyb

m7900_tyx = _ida_allins.m7900_tyx

m7900_wit = _ida_allins.m7900_wit

m7900_xab = _ida_allins.m7900_xab

m7900_last = _ida_allins.m7900_last

st9_null = _ida_allins.st9_null

st9_ld = _ida_allins.st9_ld

st9_ldw = _ida_allins.st9_ldw

st9_ldpp = _ida_allins.st9_ldpp

st9_ldpd = _ida_allins.st9_ldpd

st9_lddp = _ida_allins.st9_lddp

st9_lddd = _ida_allins.st9_lddd

st9_add = _ida_allins.st9_add

st9_addw = _ida_allins.st9_addw

st9_adc = _ida_allins.st9_adc

st9_adcw = _ida_allins.st9_adcw

st9_sub = _ida_allins.st9_sub

st9_subw = _ida_allins.st9_subw

st9_sbc = _ida_allins.st9_sbc

st9_sbcw = _ida_allins.st9_sbcw

st9_and = _ida_allins.st9_and

st9_andw = _ida_allins.st9_andw

st9_or = _ida_allins.st9_or

st9_orw = _ida_allins.st9_orw

st9_xor = _ida_allins.st9_xor

st9_xorw = _ida_allins.st9_xorw

st9_cp = _ida_allins.st9_cp

st9_cpw = _ida_allins.st9_cpw

st9_tm = _ida_allins.st9_tm

st9_tmw = _ida_allins.st9_tmw

st9_tcm = _ida_allins.st9_tcm

st9_tcmw = _ida_allins.st9_tcmw

st9_inc = _ida_allins.st9_inc

st9_incw = _ida_allins.st9_incw

st9_dec = _ida_allins.st9_dec

st9_decw = _ida_allins.st9_decw

st9_sla = _ida_allins.st9_sla

st9_slaw = _ida_allins.st9_slaw

st9_sra = _ida_allins.st9_sra

st9_sraw = _ida_allins.st9_sraw

st9_rrc = _ida_allins.st9_rrc

st9_rrcw = _ida_allins.st9_rrcw

st9_rlc = _ida_allins.st9_rlc

st9_rlcw = _ida_allins.st9_rlcw

st9_ror = _ida_allins.st9_ror

st9_rol = _ida_allins.st9_rol

st9_clr = _ida_allins.st9_clr

st9_cpl = _ida_allins.st9_cpl

st9_swap = _ida_allins.st9_swap

st9_da = _ida_allins.st9_da

st9_push = _ida_allins.st9_push

st9_pushw = _ida_allins.st9_pushw

st9_pea = _ida_allins.st9_pea

st9_pop = _ida_allins.st9_pop

st9_popw = _ida_allins.st9_popw

st9_pushu = _ida_allins.st9_pushu

st9_pushuw = _ida_allins.st9_pushuw

st9_peau = _ida_allins.st9_peau

st9_popu = _ida_allins.st9_popu

st9_popuw = _ida_allins.st9_popuw

st9_link = _ida_allins.st9_link

st9_unlink = _ida_allins.st9_unlink

st9_linku = _ida_allins.st9_linku

st9_unlinku = _ida_allins.st9_unlinku

st9_mul = _ida_allins.st9_mul

st9_div = _ida_allins.st9_div

st9_divws = _ida_allins.st9_divws

st9_bset = _ida_allins.st9_bset

st9_bres = _ida_allins.st9_bres

st9_bcpl = _ida_allins.st9_bcpl

st9_btset = _ida_allins.st9_btset

st9_bld = _ida_allins.st9_bld

st9_band = _ida_allins.st9_band

st9_bor = _ida_allins.st9_bor

st9_bxor = _ida_allins.st9_bxor

st9_ret = _ida_allins.st9_ret

st9_rets = _ida_allins.st9_rets

st9_iret = _ida_allins.st9_iret

st9_jrcc = _ida_allins.st9_jrcc

st9_jpcc = _ida_allins.st9_jpcc

st9_jp = _ida_allins.st9_jp

st9_jps = _ida_allins.st9_jps

st9_call = _ida_allins.st9_call

st9_calls = _ida_allins.st9_calls

st9_btjf = _ida_allins.st9_btjf

st9_btjt = _ida_allins.st9_btjt

st9_djnz = _ida_allins.st9_djnz

st9_dwjnz = _ida_allins.st9_dwjnz

st9_cpjfi = _ida_allins.st9_cpjfi

st9_cpjti = _ida_allins.st9_cpjti

st9_xch = _ida_allins.st9_xch

st9_srp = _ida_allins.st9_srp

st9_srp0 = _ida_allins.st9_srp0

st9_srp1 = _ida_allins.st9_srp1

st9_spp = _ida_allins.st9_spp

st9_ext = _ida_allins.st9_ext

st9_ei = _ida_allins.st9_ei

st9_di = _ida_allins.st9_di

st9_scf = _ida_allins.st9_scf

st9_rcf = _ida_allins.st9_rcf

st9_ccf = _ida_allins.st9_ccf

st9_spm = _ida_allins.st9_spm

st9_sdm = _ida_allins.st9_sdm

st9_nop = _ida_allins.st9_nop

st9_wfi = _ida_allins.st9_wfi

st9_halt = _ida_allins.st9_halt

st9_etrap = _ida_allins.st9_etrap

st9_eret = _ida_allins.st9_eret

st9_ald = _ida_allins.st9_ald

st9_aldw = _ida_allins.st9_aldw

st9_last = _ida_allins.st9_last

fr_null = _ida_allins.fr_null

fr_add = _ida_allins.fr_add

fr_add2 = _ida_allins.fr_add2

fr_addc = _ida_allins.fr_addc

fr_addn = _ida_allins.fr_addn

fr_addn2 = _ida_allins.fr_addn2

fr_sub = _ida_allins.fr_sub

fr_subc = _ida_allins.fr_subc

fr_subn = _ida_allins.fr_subn

fr_cmp = _ida_allins.fr_cmp

fr_cmp2 = _ida_allins.fr_cmp2

fr_and = _ida_allins.fr_and

fr_andh = _ida_allins.fr_andh

fr_andb = _ida_allins.fr_andb

fr_or = _ida_allins.fr_or

fr_orh = _ida_allins.fr_orh

fr_orb = _ida_allins.fr_orb

fr_eor = _ida_allins.fr_eor

fr_eorh = _ida_allins.fr_eorh

fr_eorb = _ida_allins.fr_eorb

fr_bandl = _ida_allins.fr_bandl

fr_bandh = _ida_allins.fr_bandh

fr_borl = _ida_allins.fr_borl

fr_borh = _ida_allins.fr_borh

fr_beorl = _ida_allins.fr_beorl

fr_beorh = _ida_allins.fr_beorh

fr_btstl = _ida_allins.fr_btstl

fr_btsth = _ida_allins.fr_btsth

fr_mul = _ida_allins.fr_mul

fr_mulu = _ida_allins.fr_mulu

fr_mulh = _ida_allins.fr_mulh

fr_muluh = _ida_allins.fr_muluh

fr_div0s = _ida_allins.fr_div0s

fr_div0u = _ida_allins.fr_div0u

fr_div1 = _ida_allins.fr_div1

fr_div2 = _ida_allins.fr_div2

fr_div3 = _ida_allins.fr_div3

fr_div4s = _ida_allins.fr_div4s

fr_lsl = _ida_allins.fr_lsl

fr_lsl2 = _ida_allins.fr_lsl2

fr_lsr = _ida_allins.fr_lsr

fr_lsr2 = _ida_allins.fr_lsr2

fr_asr = _ida_allins.fr_asr

fr_asr2 = _ida_allins.fr_asr2

fr_ldi_32 = _ida_allins.fr_ldi_32

fr_ldi_20 = _ida_allins.fr_ldi_20

fr_ldi_8 = _ida_allins.fr_ldi_8

fr_ld = _ida_allins.fr_ld

fr_lduh = _ida_allins.fr_lduh

fr_ldub = _ida_allins.fr_ldub

fr_st = _ida_allins.fr_st

fr_sth = _ida_allins.fr_sth

fr_stb = _ida_allins.fr_stb

fr_mov = _ida_allins.fr_mov

fr_jmp = _ida_allins.fr_jmp

fr_call = _ida_allins.fr_call

fr_ret = _ida_allins.fr_ret

fr_int = _ida_allins.fr_int

fr_inte = _ida_allins.fr_inte

fr_reti = _ida_allins.fr_reti

fr_bra = _ida_allins.fr_bra

fr_bno = _ida_allins.fr_bno

fr_beq = _ida_allins.fr_beq

fr_bne = _ida_allins.fr_bne

fr_bc = _ida_allins.fr_bc

fr_bnc = _ida_allins.fr_bnc

fr_bn = _ida_allins.fr_bn

fr_bp = _ida_allins.fr_bp

fr_bv = _ida_allins.fr_bv

fr_bnv = _ida_allins.fr_bnv

fr_blt = _ida_allins.fr_blt

fr_bge = _ida_allins.fr_bge

fr_ble = _ida_allins.fr_ble

fr_bgt = _ida_allins.fr_bgt

fr_bls = _ida_allins.fr_bls

fr_bhi = _ida_allins.fr_bhi

fr_dmov = _ida_allins.fr_dmov

fr_dmovh = _ida_allins.fr_dmovh

fr_dmovb = _ida_allins.fr_dmovb

fr_ldres = _ida_allins.fr_ldres

fr_stres = _ida_allins.fr_stres

fr_copop = _ida_allins.fr_copop

fr_copld = _ida_allins.fr_copld

fr_copst = _ida_allins.fr_copst

fr_copsv = _ida_allins.fr_copsv

fr_nop = _ida_allins.fr_nop

fr_andccr = _ida_allins.fr_andccr

fr_orccr = _ida_allins.fr_orccr

fr_stilm = _ida_allins.fr_stilm

fr_addsp = _ida_allins.fr_addsp

fr_extsb = _ida_allins.fr_extsb

fr_extub = _ida_allins.fr_extub

fr_extsh = _ida_allins.fr_extsh

fr_extuh = _ida_allins.fr_extuh

fr_ldm0 = _ida_allins.fr_ldm0

fr_ldm1 = _ida_allins.fr_ldm1

fr_stm0 = _ida_allins.fr_stm0

fr_stm1 = _ida_allins.fr_stm1

fr_enter = _ida_allins.fr_enter

fr_leave = _ida_allins.fr_leave

fr_xchb = _ida_allins.fr_xchb

fr_last = _ida_allins.fr_last

ALPHA_null = _ida_allins.ALPHA_null

ALPHA_addf = _ida_allins.ALPHA_addf

ALPHA_addg = _ida_allins.ALPHA_addg

ALPHA_addl = _ida_allins.ALPHA_addl

ALPHA_addl_v = _ida_allins.ALPHA_addl_v

ALPHA_addq = _ida_allins.ALPHA_addq

ALPHA_addq_v = _ida_allins.ALPHA_addq_v

ALPHA_adds = _ida_allins.ALPHA_adds

ALPHA_addt = _ida_allins.ALPHA_addt

ALPHA_amask = _ida_allins.ALPHA_amask

ALPHA_and = _ida_allins.ALPHA_and

ALPHA_beq = _ida_allins.ALPHA_beq

ALPHA_bge = _ida_allins.ALPHA_bge

ALPHA_bgt = _ida_allins.ALPHA_bgt

ALPHA_bic = _ida_allins.ALPHA_bic

ALPHA_bis = _ida_allins.ALPHA_bis

ALPHA_blbc = _ida_allins.ALPHA_blbc

ALPHA_blbs = _ida_allins.ALPHA_blbs

ALPHA_ble = _ida_allins.ALPHA_ble

ALPHA_blt = _ida_allins.ALPHA_blt

ALPHA_bne = _ida_allins.ALPHA_bne

ALPHA_br = _ida_allins.ALPHA_br

ALPHA_bsr = _ida_allins.ALPHA_bsr

ALPHA_call_pal = _ida_allins.ALPHA_call_pal

ALPHA_cmoveq = _ida_allins.ALPHA_cmoveq

ALPHA_cmovge = _ida_allins.ALPHA_cmovge

ALPHA_cmovgt = _ida_allins.ALPHA_cmovgt

ALPHA_cmovlbc = _ida_allins.ALPHA_cmovlbc

ALPHA_cmovlbs = _ida_allins.ALPHA_cmovlbs

ALPHA_cmovle = _ida_allins.ALPHA_cmovle

ALPHA_cmovlt = _ida_allins.ALPHA_cmovlt

ALPHA_cmovne = _ida_allins.ALPHA_cmovne

ALPHA_cmpbge = _ida_allins.ALPHA_cmpbge

ALPHA_cmpeq = _ida_allins.ALPHA_cmpeq

ALPHA_cmpgeq = _ida_allins.ALPHA_cmpgeq

ALPHA_cmpgle = _ida_allins.ALPHA_cmpgle

ALPHA_cmpglt = _ida_allins.ALPHA_cmpglt

ALPHA_cmple = _ida_allins.ALPHA_cmple

ALPHA_cmplt = _ida_allins.ALPHA_cmplt

ALPHA_cmpteq = _ida_allins.ALPHA_cmpteq

ALPHA_cmptle = _ida_allins.ALPHA_cmptle

ALPHA_cmptlt = _ida_allins.ALPHA_cmptlt

ALPHA_cmptun = _ida_allins.ALPHA_cmptun

ALPHA_cmpule = _ida_allins.ALPHA_cmpule

ALPHA_cmpult = _ida_allins.ALPHA_cmpult

ALPHA_cpys = _ida_allins.ALPHA_cpys

ALPHA_cpyse = _ida_allins.ALPHA_cpyse

ALPHA_cpysn = _ida_allins.ALPHA_cpysn

ALPHA_ctlz = _ida_allins.ALPHA_ctlz

ALPHA_ctpop = _ida_allins.ALPHA_ctpop

ALPHA_cttz = _ida_allins.ALPHA_cttz

ALPHA_cvtdg = _ida_allins.ALPHA_cvtdg

ALPHA_cvtgd = _ida_allins.ALPHA_cvtgd

ALPHA_cvtgf = _ida_allins.ALPHA_cvtgf

ALPHA_cvtgq = _ida_allins.ALPHA_cvtgq

ALPHA_cvtlq = _ida_allins.ALPHA_cvtlq

ALPHA_cvtqf = _ida_allins.ALPHA_cvtqf

ALPHA_cvtqg = _ida_allins.ALPHA_cvtqg

ALPHA_cvtql = _ida_allins.ALPHA_cvtql

ALPHA_cvtqs = _ida_allins.ALPHA_cvtqs

ALPHA_cvtqt = _ida_allins.ALPHA_cvtqt

ALPHA_cvtst = _ida_allins.ALPHA_cvtst

ALPHA_cvttq = _ida_allins.ALPHA_cvttq

ALPHA_cvtts = _ida_allins.ALPHA_cvtts

ALPHA_divf = _ida_allins.ALPHA_divf

ALPHA_divg = _ida_allins.ALPHA_divg

ALPHA_divs = _ida_allins.ALPHA_divs

ALPHA_divt = _ida_allins.ALPHA_divt

ALPHA_ecb = _ida_allins.ALPHA_ecb

ALPHA_eqv = _ida_allins.ALPHA_eqv

ALPHA_excb = _ida_allins.ALPHA_excb

ALPHA_extbl = _ida_allins.ALPHA_extbl

ALPHA_extlh = _ida_allins.ALPHA_extlh

ALPHA_extll = _ida_allins.ALPHA_extll

ALPHA_extqh = _ida_allins.ALPHA_extqh

ALPHA_extql = _ida_allins.ALPHA_extql

ALPHA_extwh = _ida_allins.ALPHA_extwh

ALPHA_extwl = _ida_allins.ALPHA_extwl

ALPHA_fbeq = _ida_allins.ALPHA_fbeq

ALPHA_fbge = _ida_allins.ALPHA_fbge

ALPHA_fbgt = _ida_allins.ALPHA_fbgt

ALPHA_fble = _ida_allins.ALPHA_fble

ALPHA_fblt = _ida_allins.ALPHA_fblt

ALPHA_fbne = _ida_allins.ALPHA_fbne

ALPHA_fcmoveq = _ida_allins.ALPHA_fcmoveq

ALPHA_fcmovge = _ida_allins.ALPHA_fcmovge

ALPHA_fcmovgt = _ida_allins.ALPHA_fcmovgt

ALPHA_fcmovle = _ida_allins.ALPHA_fcmovle

ALPHA_fcmovlt = _ida_allins.ALPHA_fcmovlt

ALPHA_fcmovne = _ida_allins.ALPHA_fcmovne

ALPHA_fetch = _ida_allins.ALPHA_fetch

ALPHA_fetch_m = _ida_allins.ALPHA_fetch_m

ALPHA_ftois = _ida_allins.ALPHA_ftois

ALPHA_ftoit = _ida_allins.ALPHA_ftoit

ALPHA_implver = _ida_allins.ALPHA_implver

ALPHA_insbl = _ida_allins.ALPHA_insbl

ALPHA_inslh = _ida_allins.ALPHA_inslh

ALPHA_insll = _ida_allins.ALPHA_insll

ALPHA_insqh = _ida_allins.ALPHA_insqh

ALPHA_insql = _ida_allins.ALPHA_insql

ALPHA_inswh = _ida_allins.ALPHA_inswh

ALPHA_inswl = _ida_allins.ALPHA_inswl

ALPHA_itoff = _ida_allins.ALPHA_itoff

ALPHA_itofs = _ida_allins.ALPHA_itofs

ALPHA_itoft = _ida_allins.ALPHA_itoft

ALPHA_jmp = _ida_allins.ALPHA_jmp

ALPHA_jsr = _ida_allins.ALPHA_jsr

ALPHA_jsr_coroutine = _ida_allins.ALPHA_jsr_coroutine

ALPHA_lda = _ida_allins.ALPHA_lda

ALPHA_ldah = _ida_allins.ALPHA_ldah

ALPHA_ldbu = _ida_allins.ALPHA_ldbu

ALPHA_ldwu = _ida_allins.ALPHA_ldwu

ALPHA_ldf = _ida_allins.ALPHA_ldf

ALPHA_ldg = _ida_allins.ALPHA_ldg

ALPHA_ldl = _ida_allins.ALPHA_ldl

ALPHA_ldl_l = _ida_allins.ALPHA_ldl_l

ALPHA_ldq = _ida_allins.ALPHA_ldq

ALPHA_ldq_l = _ida_allins.ALPHA_ldq_l

ALPHA_ldq_u = _ida_allins.ALPHA_ldq_u

ALPHA_lds = _ida_allins.ALPHA_lds

ALPHA_ldt = _ida_allins.ALPHA_ldt

ALPHA_maxsb8 = _ida_allins.ALPHA_maxsb8

ALPHA_maxsw4 = _ida_allins.ALPHA_maxsw4

ALPHA_maxub8 = _ida_allins.ALPHA_maxub8

ALPHA_maxuw4 = _ida_allins.ALPHA_maxuw4

ALPHA_mb = _ida_allins.ALPHA_mb

ALPHA_mf_fpcr = _ida_allins.ALPHA_mf_fpcr

ALPHA_minsb8 = _ida_allins.ALPHA_minsb8

ALPHA_minsw4 = _ida_allins.ALPHA_minsw4

ALPHA_minub8 = _ida_allins.ALPHA_minub8

ALPHA_minuw4 = _ida_allins.ALPHA_minuw4

ALPHA_mskbl = _ida_allins.ALPHA_mskbl

ALPHA_msklh = _ida_allins.ALPHA_msklh

ALPHA_mskll = _ida_allins.ALPHA_mskll

ALPHA_mskqh = _ida_allins.ALPHA_mskqh

ALPHA_mskql = _ida_allins.ALPHA_mskql

ALPHA_mskwh = _ida_allins.ALPHA_mskwh

ALPHA_mskwl = _ida_allins.ALPHA_mskwl

ALPHA_mt_fpcr = _ida_allins.ALPHA_mt_fpcr

ALPHA_mulf = _ida_allins.ALPHA_mulf

ALPHA_mulg = _ida_allins.ALPHA_mulg

ALPHA_mull = _ida_allins.ALPHA_mull

ALPHA_mull_v = _ida_allins.ALPHA_mull_v

ALPHA_mulq = _ida_allins.ALPHA_mulq

ALPHA_mulq_v = _ida_allins.ALPHA_mulq_v

ALPHA_muls = _ida_allins.ALPHA_muls

ALPHA_mult = _ida_allins.ALPHA_mult

ALPHA_ornot = _ida_allins.ALPHA_ornot

ALPHA_perr = _ida_allins.ALPHA_perr

ALPHA_pklb = _ida_allins.ALPHA_pklb

ALPHA_pkwb = _ida_allins.ALPHA_pkwb

ALPHA_rc = _ida_allins.ALPHA_rc

ALPHA_ret = _ida_allins.ALPHA_ret

ALPHA_rpcc = _ida_allins.ALPHA_rpcc

ALPHA_rs = _ida_allins.ALPHA_rs

ALPHA_s4addl = _ida_allins.ALPHA_s4addl

ALPHA_s4addq = _ida_allins.ALPHA_s4addq

ALPHA_s4subl = _ida_allins.ALPHA_s4subl

ALPHA_s4subq = _ida_allins.ALPHA_s4subq

ALPHA_s8addl = _ida_allins.ALPHA_s8addl

ALPHA_s8addq = _ida_allins.ALPHA_s8addq

ALPHA_s8subl = _ida_allins.ALPHA_s8subl

ALPHA_s8subq = _ida_allins.ALPHA_s8subq

ALPHA_sextb = _ida_allins.ALPHA_sextb

ALPHA_sextw = _ida_allins.ALPHA_sextw

ALPHA_sll = _ida_allins.ALPHA_sll

ALPHA_sqrtf = _ida_allins.ALPHA_sqrtf

ALPHA_sqrtg = _ida_allins.ALPHA_sqrtg

ALPHA_sqrts = _ida_allins.ALPHA_sqrts

ALPHA_sqrtt = _ida_allins.ALPHA_sqrtt

ALPHA_sra = _ida_allins.ALPHA_sra

ALPHA_srl = _ida_allins.ALPHA_srl

ALPHA_stb = _ida_allins.ALPHA_stb

ALPHA_stf = _ida_allins.ALPHA_stf

ALPHA_stg = _ida_allins.ALPHA_stg

ALPHA_sts = _ida_allins.ALPHA_sts

ALPHA_stl = _ida_allins.ALPHA_stl

ALPHA_stl_c = _ida_allins.ALPHA_stl_c

ALPHA_stq = _ida_allins.ALPHA_stq

ALPHA_stq_c = _ida_allins.ALPHA_stq_c

ALPHA_stq_u = _ida_allins.ALPHA_stq_u

ALPHA_stt = _ida_allins.ALPHA_stt

ALPHA_stw = _ida_allins.ALPHA_stw

ALPHA_subf = _ida_allins.ALPHA_subf

ALPHA_subg = _ida_allins.ALPHA_subg

ALPHA_subl = _ida_allins.ALPHA_subl

ALPHA_subl_v = _ida_allins.ALPHA_subl_v

ALPHA_subq = _ida_allins.ALPHA_subq

ALPHA_subq_v = _ida_allins.ALPHA_subq_v

ALPHA_subs = _ida_allins.ALPHA_subs

ALPHA_subt = _ida_allins.ALPHA_subt

ALPHA_trapb = _ida_allins.ALPHA_trapb

ALPHA_umulh = _ida_allins.ALPHA_umulh

ALPHA_unpkbl = _ida_allins.ALPHA_unpkbl

ALPHA_unpkbw = _ida_allins.ALPHA_unpkbw

ALPHA_wh64 = _ida_allins.ALPHA_wh64

ALPHA_wmb = _ida_allins.ALPHA_wmb

ALPHA_xor = _ida_allins.ALPHA_xor

ALPHA_zap = _ida_allins.ALPHA_zap

ALPHA_zapnot = _ida_allins.ALPHA_zapnot

ALPHA_unop = _ida_allins.ALPHA_unop

ALPHA_nop = _ida_allins.ALPHA_nop

ALPHA_fnop = _ida_allins.ALPHA_fnop

ALPHA_clr = _ida_allins.ALPHA_clr

ALPHA_fabs = _ida_allins.ALPHA_fabs

ALPHA_fclr = _ida_allins.ALPHA_fclr

ALPHA_fmov = _ida_allins.ALPHA_fmov

ALPHA_fneg = _ida_allins.ALPHA_fneg

ALPHA_mov = _ida_allins.ALPHA_mov

ALPHA_negl = _ida_allins.ALPHA_negl

ALPHA_negl_v = _ida_allins.ALPHA_negl_v

ALPHA_negq = _ida_allins.ALPHA_negq

ALPHA_negq_v = _ida_allins.ALPHA_negq_v

ALPHA_negf = _ida_allins.ALPHA_negf

ALPHA_negg = _ida_allins.ALPHA_negg

ALPHA_negs = _ida_allins.ALPHA_negs

ALPHA_negt = _ida_allins.ALPHA_negt

ALPHA_not = _ida_allins.ALPHA_not

ALPHA_sextl = _ida_allins.ALPHA_sextl

ALPHA_or = _ida_allins.ALPHA_or

ALPHA_andnot = _ida_allins.ALPHA_andnot

ALPHA_xornot = _ida_allins.ALPHA_xornot

ALPHA_br0 = _ida_allins.ALPHA_br0

ALPHA_last = _ida_allins.ALPHA_last

KR1878_null = _ida_allins.KR1878_null

KR1878_mov = _ida_allins.KR1878_mov

KR1878_cmp = _ida_allins.KR1878_cmp

KR1878_add = _ida_allins.KR1878_add

KR1878_sub = _ida_allins.KR1878_sub

KR1878_and = _ida_allins.KR1878_and

KR1878_or = _ida_allins.KR1878_or

KR1878_xor = _ida_allins.KR1878_xor

KR1878_movl = _ida_allins.KR1878_movl

KR1878_cmpl = _ida_allins.KR1878_cmpl

KR1878_addl = _ida_allins.KR1878_addl

KR1878_subl = _ida_allins.KR1878_subl

KR1878_bic = _ida_allins.KR1878_bic

KR1878_bis = _ida_allins.KR1878_bis

KR1878_btg = _ida_allins.KR1878_btg

KR1878_btt = _ida_allins.KR1878_btt

KR1878_swap = _ida_allins.KR1878_swap

KR1878_neg = _ida_allins.KR1878_neg

KR1878_not = _ida_allins.KR1878_not

KR1878_shl = _ida_allins.KR1878_shl

KR1878_shr = _ida_allins.KR1878_shr

KR1878_shra = _ida_allins.KR1878_shra

KR1878_rlc = _ida_allins.KR1878_rlc

KR1878_rrc = _ida_allins.KR1878_rrc

KR1878_adc = _ida_allins.KR1878_adc

KR1878_sbc = _ida_allins.KR1878_sbc

KR1878_ldr = _ida_allins.KR1878_ldr

KR1878_mtpr = _ida_allins.KR1878_mtpr

KR1878_mfpr = _ida_allins.KR1878_mfpr

KR1878_push = _ida_allins.KR1878_push

KR1878_pop = _ida_allins.KR1878_pop

KR1878_sst = _ida_allins.KR1878_sst

KR1878_cst = _ida_allins.KR1878_cst

KR1878_tof = _ida_allins.KR1878_tof

KR1878_tdc = _ida_allins.KR1878_tdc

KR1878_jmp = _ida_allins.KR1878_jmp

KR1878_jsr = _ida_allins.KR1878_jsr

KR1878_jnz = _ida_allins.KR1878_jnz

KR1878_jz = _ida_allins.KR1878_jz

KR1878_jns = _ida_allins.KR1878_jns

KR1878_js = _ida_allins.KR1878_js

KR1878_jnc = _ida_allins.KR1878_jnc

KR1878_jc = _ida_allins.KR1878_jc

KR1878_ijmp = _ida_allins.KR1878_ijmp

KR1878_ijsr = _ida_allins.KR1878_ijsr

KR1878_rts = _ida_allins.KR1878_rts

KR1878_rtsc = _ida_allins.KR1878_rtsc

KR1878_rti = _ida_allins.KR1878_rti

KR1878_nop = _ida_allins.KR1878_nop

KR1878_wait = _ida_allins.KR1878_wait

KR1878_stop = _ida_allins.KR1878_stop

KR1878_reset = _ida_allins.KR1878_reset

KR1878_sksp = _ida_allins.KR1878_sksp

KR1878_last = _ida_allins.KR1878_last

AD218X_null = _ida_allins.AD218X_null

AD218X_amf_01 = _ida_allins.AD218X_amf_01

AD218X_amf_03 = _ida_allins.AD218X_amf_03

AD218X_amf_02 = _ida_allins.AD218X_amf_02

AD218X_amf_04 = _ida_allins.AD218X_amf_04

AD218X_amf_05 = _ida_allins.AD218X_amf_05

AD218X_amf_06 = _ida_allins.AD218X_amf_06

AD218X_amf_07 = _ida_allins.AD218X_amf_07

AD218X_amf_08 = _ida_allins.AD218X_amf_08

AD218X_amf_09 = _ida_allins.AD218X_amf_09

AD218X_amf_0a = _ida_allins.AD218X_amf_0a

AD218X_amf_0b = _ida_allins.AD218X_amf_0b

AD218X_amf_0c = _ida_allins.AD218X_amf_0c

AD218X_amf_0d = _ida_allins.AD218X_amf_0d

AD218X_amf_0e = _ida_allins.AD218X_amf_0e

AD218X_amf_0f = _ida_allins.AD218X_amf_0f

AD218X_amf_10 = _ida_allins.AD218X_amf_10

AD218X_amf_11 = _ida_allins.AD218X_amf_11

AD218X_amf_12 = _ida_allins.AD218X_amf_12

AD218X_amf_13 = _ida_allins.AD218X_amf_13

AD218X_amf_14 = _ida_allins.AD218X_amf_14

AD218X_amf_15 = _ida_allins.AD218X_amf_15

AD218X_amf_16 = _ida_allins.AD218X_amf_16

AD218X_amf_17 = _ida_allins.AD218X_amf_17

AD218X_amf_18 = _ida_allins.AD218X_amf_18

AD218X_amf_19 = _ida_allins.AD218X_amf_19

AD218X_amf_1a = _ida_allins.AD218X_amf_1a

AD218X_amf_1b = _ida_allins.AD218X_amf_1b

AD218X_amf_1c = _ida_allins.AD218X_amf_1c

AD218X_amf_1d = _ida_allins.AD218X_amf_1d

AD218X_amf_1e = _ida_allins.AD218X_amf_1e

AD218X_amf_1f = _ida_allins.AD218X_amf_1f

AD218X_shft_0 = _ida_allins.AD218X_shft_0

AD218X_shft_1 = _ida_allins.AD218X_shft_1

AD218X_shft_2 = _ida_allins.AD218X_shft_2

AD218X_shft_3 = _ida_allins.AD218X_shft_3

AD218X_shft_4 = _ida_allins.AD218X_shft_4

AD218X_shft_5 = _ida_allins.AD218X_shft_5

AD218X_shft_6 = _ida_allins.AD218X_shft_6

AD218X_shft_7 = _ida_allins.AD218X_shft_7

AD218X_shft_8 = _ida_allins.AD218X_shft_8

AD218X_shft_9 = _ida_allins.AD218X_shft_9

AD218X_shft_a = _ida_allins.AD218X_shft_a

AD218X_shft_b = _ida_allins.AD218X_shft_b

AD218X_shft_c = _ida_allins.AD218X_shft_c

AD218X_shft_d = _ida_allins.AD218X_shft_d

AD218X_shft_e = _ida_allins.AD218X_shft_e

AD218X_shft_f = _ida_allins.AD218X_shft_f

AD218X_alu_00 = _ida_allins.AD218X_alu_00

AD218X_alu_01 = _ida_allins.AD218X_alu_01

AD218X_alu_02 = _ida_allins.AD218X_alu_02

AD218X_alu_03 = _ida_allins.AD218X_alu_03

AD218X_alu_04 = _ida_allins.AD218X_alu_04

AD218X_alu_05 = _ida_allins.AD218X_alu_05

AD218X_alu_06 = _ida_allins.AD218X_alu_06

AD218X_alu_07 = _ida_allins.AD218X_alu_07

AD218X_alu_08 = _ida_allins.AD218X_alu_08

AD218X_alu_09 = _ida_allins.AD218X_alu_09

AD218X_alu_0a = _ida_allins.AD218X_alu_0a

AD218X_alu_0b = _ida_allins.AD218X_alu_0b

AD218X_alu_0c = _ida_allins.AD218X_alu_0c

AD218X_alu_0d = _ida_allins.AD218X_alu_0d

AD218X_alu_0e = _ida_allins.AD218X_alu_0e

AD218X_alu_0f = _ida_allins.AD218X_alu_0f

AD218X_alu_10 = _ida_allins.AD218X_alu_10

AD218X_alu_11 = _ida_allins.AD218X_alu_11

AD218X_alu_12 = _ida_allins.AD218X_alu_12

AD218X_alu_13 = _ida_allins.AD218X_alu_13

AD218X_alu_14 = _ida_allins.AD218X_alu_14

AD218X_alu_15 = _ida_allins.AD218X_alu_15

AD218X_alu_16 = _ida_allins.AD218X_alu_16

AD218X_alu_17 = _ida_allins.AD218X_alu_17

AD218X_alu_18 = _ida_allins.AD218X_alu_18

AD218X_alu_19 = _ida_allins.AD218X_alu_19

AD218X_alu_1a = _ida_allins.AD218X_alu_1a

AD218X_alu_1b = _ida_allins.AD218X_alu_1b

AD218X_alu_1c = _ida_allins.AD218X_alu_1c

AD218X_alu_1d = _ida_allins.AD218X_alu_1d

AD218X_mac_0 = _ida_allins.AD218X_mac_0

AD218X_mac_1 = _ida_allins.AD218X_mac_1

AD218X_mac_2 = _ida_allins.AD218X_mac_2

AD218X_mac_3 = _ida_allins.AD218X_mac_3

AD218X_mac_4 = _ida_allins.AD218X_mac_4

AD218X_mac_5 = _ida_allins.AD218X_mac_5

AD218X_mac_6 = _ida_allins.AD218X_mac_6

AD218X_mac_7 = _ida_allins.AD218X_mac_7

AD218X_mac_8 = _ida_allins.AD218X_mac_8

AD218X_mac_9 = _ida_allins.AD218X_mac_9

AD218X_mac_a = _ida_allins.AD218X_mac_a

AD218X_mac_b = _ida_allins.AD218X_mac_b

AD218X_amf = _ida_allins.AD218X_amf

AD218X_shft = _ida_allins.AD218X_shft

AD218X_shifter_0 = _ida_allins.AD218X_shifter_0

AD218X_shifter_1 = _ida_allins.AD218X_shifter_1

AD218X_shifter_2 = _ida_allins.AD218X_shifter_2

AD218X_shifter_3 = _ida_allins.AD218X_shifter_3

AD218X_shifter_4 = _ida_allins.AD218X_shifter_4

AD218X_shifter_5 = _ida_allins.AD218X_shifter_5

AD218X_shifter_6 = _ida_allins.AD218X_shifter_6

AD218X_shifter_7 = _ida_allins.AD218X_shifter_7

AD218X_move_0 = _ida_allins.AD218X_move_0

AD218X_move_1 = _ida_allins.AD218X_move_1

AD218X_move_2 = _ida_allins.AD218X_move_2

AD218X_move_3 = _ida_allins.AD218X_move_3

AD218X_move_4 = _ida_allins.AD218X_move_4

AD218X_move_5 = _ida_allins.AD218X_move_5

AD218X_move_6 = _ida_allins.AD218X_move_6

AD218X_move_7 = _ida_allins.AD218X_move_7

AD218X_move_8 = _ida_allins.AD218X_move_8

AD218X_move_9 = _ida_allins.AD218X_move_9

AD218X_move_a = _ida_allins.AD218X_move_a

AD218X_move_b = _ida_allins.AD218X_move_b

AD218X_jump = _ida_allins.AD218X_jump

AD218X_jump_1 = _ida_allins.AD218X_jump_1

AD218X_jump_2 = _ida_allins.AD218X_jump_2

AD218X_jump_3 = _ida_allins.AD218X_jump_3

AD218X_jump_4 = _ida_allins.AD218X_jump_4

AD218X_call = _ida_allins.AD218X_call

AD218X_call_1 = _ida_allins.AD218X_call_1

AD218X_call_2 = _ida_allins.AD218X_call_2

AD218X_rts = _ida_allins.AD218X_rts

AD218X_rts_cond = _ida_allins.AD218X_rts_cond

AD218X_rti = _ida_allins.AD218X_rti

AD218X_rti_cond = _ida_allins.AD218X_rti_cond

AD218X_nop = _ida_allins.AD218X_nop

AD218X_do = _ida_allins.AD218X_do

AD218X_idle = _ida_allins.AD218X_idle

AD218X_idle_1 = _ida_allins.AD218X_idle_1

AD218X_flag_out = _ida_allins.AD218X_flag_out

AD218X_stack_ctl = _ida_allins.AD218X_stack_ctl

AD218X_mode_ctl = _ida_allins.AD218X_mode_ctl

AD218X_tops_w = _ida_allins.AD218X_tops_w

AD218X_tops_r = _ida_allins.AD218X_tops_r

AD218X_ints_dis = _ida_allins.AD218X_ints_dis

AD218X_ints_ena = _ida_allins.AD218X_ints_ena

AD218X_modify = _ida_allins.AD218X_modify

AD218X_double_move = _ida_allins.AD218X_double_move

AD218X_amf_move_0 = _ida_allins.AD218X_amf_move_0

AD218X_amf_move_1 = _ida_allins.AD218X_amf_move_1

AD218X_amf_move_2 = _ida_allins.AD218X_amf_move_2

AD218X_amf_move_3 = _ida_allins.AD218X_amf_move_3

AD218X_amf_move_4 = _ida_allins.AD218X_amf_move_4

AD218X_amf_move_5 = _ida_allins.AD218X_amf_move_5

AD218X_amf_move_6 = _ida_allins.AD218X_amf_move_6

AD218X_amf_move_7 = _ida_allins.AD218X_amf_move_7

AD218X_amf_move_8 = _ida_allins.AD218X_amf_move_8

AD218X_amf_move_9 = _ida_allins.AD218X_amf_move_9

AD218X_amf_move_a = _ida_allins.AD218X_amf_move_a

AD218X_last = _ida_allins.AD218X_last

OAK_Dsp_null = _ida_allins.OAK_Dsp_null

OAK_Dsp_proc = _ida_allins.OAK_Dsp_proc

OAK_Dsp_or = _ida_allins.OAK_Dsp_or

OAK_Dsp_and = _ida_allins.OAK_Dsp_and

OAK_Dsp_xor = _ida_allins.OAK_Dsp_xor

OAK_Dsp_add = _ida_allins.OAK_Dsp_add

OAK_Dsp_alm_tst0 = _ida_allins.OAK_Dsp_alm_tst0

OAK_Dsp_alm_tst1 = _ida_allins.OAK_Dsp_alm_tst1

OAK_Dsp_cmp = _ida_allins.OAK_Dsp_cmp

OAK_Dsp_sub = _ida_allins.OAK_Dsp_sub

OAK_Dsp_alm_msu = _ida_allins.OAK_Dsp_alm_msu

OAK_Dsp_addh = _ida_allins.OAK_Dsp_addh

OAK_Dsp_addl = _ida_allins.OAK_Dsp_addl

OAK_Dsp_subh = _ida_allins.OAK_Dsp_subh

OAK_Dsp_subl = _ida_allins.OAK_Dsp_subl

OAK_Dsp_sqr = _ida_allins.OAK_Dsp_sqr

OAK_Dsp_sqra = _ida_allins.OAK_Dsp_sqra

OAK_Dsp_cmpu = _ida_allins.OAK_Dsp_cmpu

OAK_Dsp_shr = _ida_allins.OAK_Dsp_shr

OAK_Dsp_shr4 = _ida_allins.OAK_Dsp_shr4

OAK_Dsp_shl = _ida_allins.OAK_Dsp_shl

OAK_Dsp_shl4 = _ida_allins.OAK_Dsp_shl4

OAK_Dsp_ror = _ida_allins.OAK_Dsp_ror

OAK_Dsp_rol = _ida_allins.OAK_Dsp_rol

OAK_Dsp_clr = _ida_allins.OAK_Dsp_clr

OAK_Dsp_mod_reserved = _ida_allins.OAK_Dsp_mod_reserved

OAK_Dsp_not = _ida_allins.OAK_Dsp_not

OAK_Dsp_neg = _ida_allins.OAK_Dsp_neg

OAK_Dsp_rnd = _ida_allins.OAK_Dsp_rnd

OAK_Dsp_pacr = _ida_allins.OAK_Dsp_pacr

OAK_Dsp_clrr = _ida_allins.OAK_Dsp_clrr

OAK_Dsp_inc = _ida_allins.OAK_Dsp_inc

OAK_Dsp_dec = _ida_allins.OAK_Dsp_dec

OAK_Dsp_copy = _ida_allins.OAK_Dsp_copy

OAK_Dsp_norm = _ida_allins.OAK_Dsp_norm

OAK_Dsp_divs = _ida_allins.OAK_Dsp_divs

OAK_Dsp_set = _ida_allins.OAK_Dsp_set

OAK_Dsp_rst = _ida_allins.OAK_Dsp_rst

OAK_Dsp_chng = _ida_allins.OAK_Dsp_chng

OAK_Dsp_addv = _ida_allins.OAK_Dsp_addv

OAK_Dsp_alb_tst0 = _ida_allins.OAK_Dsp_alb_tst0

OAK_Dsp_alb_tst1 = _ida_allins.OAK_Dsp_alb_tst1

OAK_Dsp_cmpv = _ida_allins.OAK_Dsp_cmpv

OAK_Dsp_subv = _ida_allins.OAK_Dsp_subv

OAK_Dsp_maxd = _ida_allins.OAK_Dsp_maxd

OAK_Dsp_max = _ida_allins.OAK_Dsp_max

OAK_Dsp_min = _ida_allins.OAK_Dsp_min

OAK_Dsp_lim = _ida_allins.OAK_Dsp_lim

OAK_Dsp_mpy = _ida_allins.OAK_Dsp_mpy

OAK_Dsp_mpysu = _ida_allins.OAK_Dsp_mpysu

OAK_Dsp_mac = _ida_allins.OAK_Dsp_mac

OAK_Dsp_macus = _ida_allins.OAK_Dsp_macus

OAK_Dsp_maa = _ida_allins.OAK_Dsp_maa

OAK_Dsp_macuu = _ida_allins.OAK_Dsp_macuu

OAK_Dsp_macsu = _ida_allins.OAK_Dsp_macsu

OAK_Dsp_maasu = _ida_allins.OAK_Dsp_maasu

OAK_Dsp_mpyi = _ida_allins.OAK_Dsp_mpyi

OAK_Dsp_msu = _ida_allins.OAK_Dsp_msu

OAK_Dsp_tstb = _ida_allins.OAK_Dsp_tstb

OAK_Dsp_shfc = _ida_allins.OAK_Dsp_shfc

OAK_Dsp_shfi = _ida_allins.OAK_Dsp_shfi

OAK_Dsp_exp = _ida_allins.OAK_Dsp_exp

OAK_Dsp_mov = _ida_allins.OAK_Dsp_mov

OAK_Dsp_movp = _ida_allins.OAK_Dsp_movp

OAK_Dsp_movs = _ida_allins.OAK_Dsp_movs

OAK_Dsp_movsi = _ida_allins.OAK_Dsp_movsi

OAK_Dsp_movr = _ida_allins.OAK_Dsp_movr

OAK_Dsp_movd = _ida_allins.OAK_Dsp_movd

OAK_Dsp_push = _ida_allins.OAK_Dsp_push

OAK_Dsp_pop = _ida_allins.OAK_Dsp_pop

OAK_Dsp_swap = _ida_allins.OAK_Dsp_swap

OAK_Dsp_banke = _ida_allins.OAK_Dsp_banke

OAK_Dsp_rep = _ida_allins.OAK_Dsp_rep

OAK_Dsp_bkrep = _ida_allins.OAK_Dsp_bkrep

OAK_Dsp_break = _ida_allins.OAK_Dsp_break

OAK_Dsp_br = _ida_allins.OAK_Dsp_br

OAK_Dsp_brr = _ida_allins.OAK_Dsp_brr

OAK_Dsp_br_u = _ida_allins.OAK_Dsp_br_u

OAK_Dsp_brr_u = _ida_allins.OAK_Dsp_brr_u

OAK_Dsp_call = _ida_allins.OAK_Dsp_call

OAK_Dsp_callr = _ida_allins.OAK_Dsp_callr

OAK_Dsp_calla = _ida_allins.OAK_Dsp_calla

OAK_Dsp_ret = _ida_allins.OAK_Dsp_ret

OAK_Dsp_ret_u = _ida_allins.OAK_Dsp_ret_u

OAK_Dsp_retd = _ida_allins.OAK_Dsp_retd

OAK_Dsp_reti = _ida_allins.OAK_Dsp_reti

OAK_Dsp_reti_u = _ida_allins.OAK_Dsp_reti_u

OAK_Dsp_retid = _ida_allins.OAK_Dsp_retid

OAK_Dsp_rets = _ida_allins.OAK_Dsp_rets

OAK_Dsp_cntx = _ida_allins.OAK_Dsp_cntx

OAK_Dsp_nop = _ida_allins.OAK_Dsp_nop

OAK_Dsp_modr = _ida_allins.OAK_Dsp_modr

OAK_Dsp_dint = _ida_allins.OAK_Dsp_dint

OAK_Dsp_eint = _ida_allins.OAK_Dsp_eint

OAK_Dsp_trap = _ida_allins.OAK_Dsp_trap

OAK_Dsp_lpg = _ida_allins.OAK_Dsp_lpg

OAK_Dsp_load = _ida_allins.OAK_Dsp_load

OAK_Dsp_mov_eu = _ida_allins.OAK_Dsp_mov_eu

OAK_Dsp_last = _ida_allins.OAK_Dsp_last

T900_null = _ida_allins.T900_null

T900_ld = _ida_allins.T900_ld

T900_ldw = _ida_allins.T900_ldw

T900_push = _ida_allins.T900_push

T900_pushw = _ida_allins.T900_pushw

T900_pop = _ida_allins.T900_pop

T900_popw = _ida_allins.T900_popw

T900_lda = _ida_allins.T900_lda

T900_ldar = _ida_allins.T900_ldar

T900_ex = _ida_allins.T900_ex

T900_mirr = _ida_allins.T900_mirr

T900_ldi = _ida_allins.T900_ldi

T900_ldiw = _ida_allins.T900_ldiw

T900_ldir = _ida_allins.T900_ldir

T900_ldirw = _ida_allins.T900_ldirw

T900_ldd = _ida_allins.T900_ldd

T900_lddw = _ida_allins.T900_lddw

T900_lddr = _ida_allins.T900_lddr

T900_lddrw = _ida_allins.T900_lddrw

T900_cpi = _ida_allins.T900_cpi

T900_cpir = _ida_allins.T900_cpir

T900_cpd = _ida_allins.T900_cpd

T900_cpdr = _ida_allins.T900_cpdr

T900_add = _ida_allins.T900_add

T900_addw = _ida_allins.T900_addw

T900_adc = _ida_allins.T900_adc

T900_adcw = _ida_allins.T900_adcw

T900_sub = _ida_allins.T900_sub

T900_subw = _ida_allins.T900_subw

T900_sbc = _ida_allins.T900_sbc

T900_sbcw = _ida_allins.T900_sbcw

T900_cp = _ida_allins.T900_cp

T900_cpw = _ida_allins.T900_cpw

T900_inc = _ida_allins.T900_inc

T900_incw = _ida_allins.T900_incw

T900_dec = _ida_allins.T900_dec

T900_decw = _ida_allins.T900_decw

T900_neg = _ida_allins.T900_neg

T900_extz = _ida_allins.T900_extz

T900_exts = _ida_allins.T900_exts

T900_daa = _ida_allins.T900_daa

T900_paa = _ida_allins.T900_paa

T900_cpl = _ida_allins.T900_cpl

T900_mul = _ida_allins.T900_mul

T900_muls = _ida_allins.T900_muls

T900_div = _ida_allins.T900_div

T900_divs = _ida_allins.T900_divs

T900_mula = _ida_allins.T900_mula

T900_minc1 = _ida_allins.T900_minc1

T900_minc2 = _ida_allins.T900_minc2

T900_minc4 = _ida_allins.T900_minc4

T900_mdec1 = _ida_allins.T900_mdec1

T900_mdec2 = _ida_allins.T900_mdec2

T900_mdec4 = _ida_allins.T900_mdec4

T900_and = _ida_allins.T900_and

T900_andw = _ida_allins.T900_andw

T900_or = _ida_allins.T900_or

T900_orw = _ida_allins.T900_orw

T900_xor = _ida_allins.T900_xor

T900_xorw = _ida_allins.T900_xorw

T900_ldcf = _ida_allins.T900_ldcf

T900_stcf = _ida_allins.T900_stcf

T900_andcf = _ida_allins.T900_andcf

T900_orcf = _ida_allins.T900_orcf

T900_xorcf = _ida_allins.T900_xorcf

T900_rcf = _ida_allins.T900_rcf

T900_scf = _ida_allins.T900_scf

T900_ccf = _ida_allins.T900_ccf

T900_zcf = _ida_allins.T900_zcf

T900_bit = _ida_allins.T900_bit

T900_res = _ida_allins.T900_res

T900_set = _ida_allins.T900_set

T900_chg = _ida_allins.T900_chg

T900_tset = _ida_allins.T900_tset

T900_bs1f = _ida_allins.T900_bs1f

T900_bs1b = _ida_allins.T900_bs1b

T900_nop = _ida_allins.T900_nop

T900_ei = _ida_allins.T900_ei

T900_di = _ida_allins.T900_di

T900_swi = _ida_allins.T900_swi

T900_halt = _ida_allins.T900_halt

T900_ldc = _ida_allins.T900_ldc

T900_ldx = _ida_allins.T900_ldx

T900_link = _ida_allins.T900_link

T900_unlk = _ida_allins.T900_unlk

T900_ldf = _ida_allins.T900_ldf

T900_incf = _ida_allins.T900_incf

T900_decf = _ida_allins.T900_decf

T900_scc = _ida_allins.T900_scc

T900_rlc = _ida_allins.T900_rlc

T900_rlc_mem = _ida_allins.T900_rlc_mem

T900_rlcw_mem = _ida_allins.T900_rlcw_mem

T900_rrc = _ida_allins.T900_rrc

T900_rrc_mem = _ida_allins.T900_rrc_mem

T900_rrcw_mem = _ida_allins.T900_rrcw_mem

T900_rl = _ida_allins.T900_rl

T900_rl_mem = _ida_allins.T900_rl_mem

T900_rlw_mem = _ida_allins.T900_rlw_mem

T900_rr = _ida_allins.T900_rr

T900_rr_mem = _ida_allins.T900_rr_mem

T900_rrw_mem = _ida_allins.T900_rrw_mem

T900_sla = _ida_allins.T900_sla

T900_sla_mem = _ida_allins.T900_sla_mem

T900_slaw_mem = _ida_allins.T900_slaw_mem

T900_sra = _ida_allins.T900_sra

T900_sra_mem = _ida_allins.T900_sra_mem

T900_sraw_mem = _ida_allins.T900_sraw_mem

T900_sll = _ida_allins.T900_sll

T900_sll_mem = _ida_allins.T900_sll_mem

T900_sllw_mem = _ida_allins.T900_sllw_mem

T900_srl = _ida_allins.T900_srl

T900_srl_mem = _ida_allins.T900_srl_mem

T900_srlw_mem = _ida_allins.T900_srlw_mem

T900_rld = _ida_allins.T900_rld

T900_rrd = _ida_allins.T900_rrd

T900_jp = _ida_allins.T900_jp

T900_jp_cond = _ida_allins.T900_jp_cond

T900_jr = _ida_allins.T900_jr

T900_jr_cond = _ida_allins.T900_jr_cond

T900_jrl = _ida_allins.T900_jrl

T900_jrl_cond = _ida_allins.T900_jrl_cond

T900_call = _ida_allins.T900_call

T900_calr = _ida_allins.T900_calr

T900_djnz = _ida_allins.T900_djnz

T900_ret = _ida_allins.T900_ret

T900_ret_cond = _ida_allins.T900_ret_cond

T900_retd = _ida_allins.T900_retd

T900_reti = _ida_allins.T900_reti

T900_max = _ida_allins.T900_max

T900_normal = _ida_allins.T900_normal

T900_last = _ida_allins.T900_last

C39_null = _ida_allins.C39_null

C39_adc = _ida_allins.C39_adc

C39_add = _ida_allins.C39_add

C39_anc = _ida_allins.C39_anc

C39_and = _ida_allins.C39_and

C39_ane = _ida_allins.C39_ane

C39_arr = _ida_allins.C39_arr

C39_asl = _ida_allins.C39_asl

C39_asr = _ida_allins.C39_asr

C39_bar = _ida_allins.C39_bar

C39_bas = _ida_allins.C39_bas

C39_bbr = _ida_allins.C39_bbr

C39_bbs = _ida_allins.C39_bbs

C39_bcc = _ida_allins.C39_bcc

C39_bcs = _ida_allins.C39_bcs

C39_beq = _ida_allins.C39_beq

C39_bit = _ida_allins.C39_bit

C39_bmi = _ida_allins.C39_bmi

C39_bne = _ida_allins.C39_bne

C39_bpl = _ida_allins.C39_bpl

C39_bra = _ida_allins.C39_bra

C39_brk = _ida_allins.C39_brk

C39_bvc = _ida_allins.C39_bvc

C39_bvs = _ida_allins.C39_bvs

C39_clc = _ida_allins.C39_clc

C39_cld = _ida_allins.C39_cld

C39_cli = _ida_allins.C39_cli

C39_clv = _ida_allins.C39_clv

C39_clw = _ida_allins.C39_clw

C39_cmp = _ida_allins.C39_cmp

C39_cpx = _ida_allins.C39_cpx

C39_cpy = _ida_allins.C39_cpy

C39_dcp = _ida_allins.C39_dcp

C39_dec = _ida_allins.C39_dec

C39_dex = _ida_allins.C39_dex

C39_dey = _ida_allins.C39_dey

C39_eor = _ida_allins.C39_eor

C39_exc = _ida_allins.C39_exc

C39_inc = _ida_allins.C39_inc

C39_ini = _ida_allins.C39_ini

C39_inx = _ida_allins.C39_inx

C39_iny = _ida_allins.C39_iny

C39_isb = _ida_allins.C39_isb

C39_jmp = _ida_allins.C39_jmp

C39_jpi = _ida_allins.C39_jpi

C39_jsb = _ida_allins.C39_jsb

C39_jsr = _ida_allins.C39_jsr

C39_lab = _ida_allins.C39_lab

C39_lae = _ida_allins.C39_lae

C39_lai = _ida_allins.C39_lai

C39_lan = _ida_allins.C39_lan

C39_lax = _ida_allins.C39_lax

C39_lda = _ida_allins.C39_lda

C39_ldx = _ida_allins.C39_ldx

C39_ldy = _ida_allins.C39_ldy

C39_lii = _ida_allins.C39_lii

C39_lsr = _ida_allins.C39_lsr

C39_lxa = _ida_allins.C39_lxa

C39_mpa = _ida_allins.C39_mpa

C39_mpy = _ida_allins.C39_mpy

C39_neg = _ida_allins.C39_neg

C39_nop = _ida_allins.C39_nop

C39_nxt = _ida_allins.C39_nxt

C39_ora = _ida_allins.C39_ora

C39_pha = _ida_allins.C39_pha

C39_phi = _ida_allins.C39_phi

C39_php = _ida_allins.C39_php

C39_phw = _ida_allins.C39_phw

C39_phx = _ida_allins.C39_phx

C39_phy = _ida_allins.C39_phy

C39_pia = _ida_allins.C39_pia

C39_pla = _ida_allins.C39_pla

C39_pli = _ida_allins.C39_pli

C39_plp = _ida_allins.C39_plp

C39_plw = _ida_allins.C39_plw

C39_plx = _ida_allins.C39_plx

C39_ply = _ida_allins.C39_ply

C39_psh = _ida_allins.C39_psh

C39_pul = _ida_allins.C39_pul

C39_rba = _ida_allins.C39_rba

C39_rla = _ida_allins.C39_rla

C39_rmb = _ida_allins.C39_rmb

C39_rnd = _ida_allins.C39_rnd

C39_rol = _ida_allins.C39_rol

C39_ror = _ida_allins.C39_ror

C39_rra = _ida_allins.C39_rra

C39_rti = _ida_allins.C39_rti

C39_rts = _ida_allins.C39_rts

C39_sax = _ida_allins.C39_sax

C39_sba = _ida_allins.C39_sba

C39_sbc = _ida_allins.C39_sbc

C39_sbx = _ida_allins.C39_sbx

C39_sec = _ida_allins.C39_sec

C39_sed = _ida_allins.C39_sed

C39_sei = _ida_allins.C39_sei

C39_sha = _ida_allins.C39_sha

C39_shs = _ida_allins.C39_shs

C39_shx = _ida_allins.C39_shx

C39_shy = _ida_allins.C39_shy

C39_slo = _ida_allins.C39_slo

C39_smb = _ida_allins.C39_smb

C39_sre = _ida_allins.C39_sre

C39_sta = _ida_allins.C39_sta

C39_sti = _ida_allins.C39_sti

C39_stx = _ida_allins.C39_stx

C39_sty = _ida_allins.C39_sty

C39_tax = _ida_allins.C39_tax

C39_tay = _ida_allins.C39_tay

C39_taw = _ida_allins.C39_taw

C39_tip = _ida_allins.C39_tip

C39_tsx = _ida_allins.C39_tsx

C39_twa = _ida_allins.C39_twa

C39_txa = _ida_allins.C39_txa

C39_txs = _ida_allins.C39_txs

C39_tya = _ida_allins.C39_tya

C39_last = _ida_allins.C39_last

CR16_null = _ida_allins.CR16_null

CR16_addb = _ida_allins.CR16_addb

CR16_addw = _ida_allins.CR16_addw

CR16_addub = _ida_allins.CR16_addub

CR16_adduw = _ida_allins.CR16_adduw

CR16_addcb = _ida_allins.CR16_addcb

CR16_addcw = _ida_allins.CR16_addcw

CR16_andb = _ida_allins.CR16_andb

CR16_andw = _ida_allins.CR16_andw

CR16_ashub = _ida_allins.CR16_ashub

CR16_ashuw = _ida_allins.CR16_ashuw

CR16_beq = _ida_allins.CR16_beq

CR16_bne = _ida_allins.CR16_bne

CR16_bcs = _ida_allins.CR16_bcs

CR16_bcc = _ida_allins.CR16_bcc

CR16_bhi = _ida_allins.CR16_bhi

CR16_bls = _ida_allins.CR16_bls

CR16_bgt = _ida_allins.CR16_bgt

CR16_ble = _ida_allins.CR16_ble

CR16_bfs = _ida_allins.CR16_bfs

CR16_bfc = _ida_allins.CR16_bfc

CR16_blo = _ida_allins.CR16_blo

CR16_bhs = _ida_allins.CR16_bhs

CR16_blt = _ida_allins.CR16_blt

CR16_bge = _ida_allins.CR16_bge

CR16_br = _ida_allins.CR16_br

CR16_bal = _ida_allins.CR16_bal

CR16_cmpb = _ida_allins.CR16_cmpb

CR16_cmpw = _ida_allins.CR16_cmpw

CR16_beq1b = _ida_allins.CR16_beq1b

CR16_beq1w = _ida_allins.CR16_beq1w

CR16_beq0b = _ida_allins.CR16_beq0b

CR16_beq0w = _ida_allins.CR16_beq0w

CR16_bne1b = _ida_allins.CR16_bne1b

CR16_bne1w = _ida_allins.CR16_bne1w

CR16_bne0b = _ida_allins.CR16_bne0b

CR16_bne0w = _ida_allins.CR16_bne0w

CR16_di = _ida_allins.CR16_di

CR16_ei = _ida_allins.CR16_ei

CR16_excp = _ida_allins.CR16_excp

CR16_jeq = _ida_allins.CR16_jeq

CR16_jne = _ida_allins.CR16_jne

CR16_jcs = _ida_allins.CR16_jcs

CR16_jcc = _ida_allins.CR16_jcc

CR16_jhi = _ida_allins.CR16_jhi

CR16_jls = _ida_allins.CR16_jls

CR16_jgt = _ida_allins.CR16_jgt

CR16_jle = _ida_allins.CR16_jle

CR16_jfs = _ida_allins.CR16_jfs

CR16_jfc = _ida_allins.CR16_jfc

CR16_jlo = _ida_allins.CR16_jlo

CR16_jhs = _ida_allins.CR16_jhs

CR16_jlt = _ida_allins.CR16_jlt

CR16_jge = _ida_allins.CR16_jge

CR16_jump = _ida_allins.CR16_jump

CR16_jal = _ida_allins.CR16_jal

CR16_loadb = _ida_allins.CR16_loadb

CR16_loadw = _ida_allins.CR16_loadw

CR16_loadm = _ida_allins.CR16_loadm

CR16_lpr = _ida_allins.CR16_lpr

CR16_lshb = _ida_allins.CR16_lshb

CR16_lshw = _ida_allins.CR16_lshw

CR16_movb = _ida_allins.CR16_movb

CR16_movw = _ida_allins.CR16_movw

CR16_movxb = _ida_allins.CR16_movxb

CR16_movzb = _ida_allins.CR16_movzb

CR16_movd = _ida_allins.CR16_movd

CR16_mulb = _ida_allins.CR16_mulb

CR16_mulw = _ida_allins.CR16_mulw

CR16_mulsb = _ida_allins.CR16_mulsb

CR16_mulsw = _ida_allins.CR16_mulsw

CR16_muluw = _ida_allins.CR16_muluw

CR16_nop = _ida_allins.CR16_nop

CR16_orb = _ida_allins.CR16_orb

CR16_orw = _ida_allins.CR16_orw

CR16_push = _ida_allins.CR16_push

CR16_pop = _ida_allins.CR16_pop

CR16_popret = _ida_allins.CR16_popret

CR16_retx = _ida_allins.CR16_retx

CR16_seq = _ida_allins.CR16_seq

CR16_sne = _ida_allins.CR16_sne

CR16_scs = _ida_allins.CR16_scs

CR16_scc = _ida_allins.CR16_scc

CR16_shi = _ida_allins.CR16_shi

CR16_sls = _ida_allins.CR16_sls

CR16_sgt = _ida_allins.CR16_sgt

CR16_sle = _ida_allins.CR16_sle

CR16_sfs = _ida_allins.CR16_sfs

CR16_sfc = _ida_allins.CR16_sfc

CR16_slo = _ida_allins.CR16_slo

CR16_shs = _ida_allins.CR16_shs

CR16_slt = _ida_allins.CR16_slt

CR16_sge = _ida_allins.CR16_sge

CR16_spr = _ida_allins.CR16_spr

CR16_storb = _ida_allins.CR16_storb

CR16_storw = _ida_allins.CR16_storw

CR16_storm = _ida_allins.CR16_storm

CR16_subb = _ida_allins.CR16_subb

CR16_subw = _ida_allins.CR16_subw

CR16_subcb = _ida_allins.CR16_subcb

CR16_subcw = _ida_allins.CR16_subcw

CR16_tbit = _ida_allins.CR16_tbit

CR16_tbitb = _ida_allins.CR16_tbitb

CR16_tbitw = _ida_allins.CR16_tbitw

CR16_sbitb = _ida_allins.CR16_sbitb

CR16_sbitw = _ida_allins.CR16_sbitw

CR16_cbitb = _ida_allins.CR16_cbitb

CR16_cbitw = _ida_allins.CR16_cbitw

CR16_wait = _ida_allins.CR16_wait

CR16_eiwait = _ida_allins.CR16_eiwait

CR16_xorb = _ida_allins.CR16_xorb

CR16_xorw = _ida_allins.CR16_xorw

CR16_last = _ida_allins.CR16_last

mn102_null = _ida_allins.mn102_null

mn102_add = _ida_allins.mn102_add

mn102_addc = _ida_allins.mn102_addc

mn102_addnf = _ida_allins.mn102_addnf

mn102_and = _ida_allins.mn102_and

mn102_asr = _ida_allins.mn102_asr

mn102_bcc = _ida_allins.mn102_bcc

mn102_bccx = _ida_allins.mn102_bccx

mn102_bclr = _ida_allins.mn102_bclr

mn102_bcs = _ida_allins.mn102_bcs

mn102_bcsx = _ida_allins.mn102_bcsx

mn102_beq = _ida_allins.mn102_beq

mn102_beqx = _ida_allins.mn102_beqx

mn102_bge = _ida_allins.mn102_bge

mn102_bgex = _ida_allins.mn102_bgex

mn102_bgt = _ida_allins.mn102_bgt

mn102_bgtx = _ida_allins.mn102_bgtx

mn102_bhi = _ida_allins.mn102_bhi

mn102_bhix = _ida_allins.mn102_bhix

mn102_ble = _ida_allins.mn102_ble

mn102_blex = _ida_allins.mn102_blex

mn102_bls = _ida_allins.mn102_bls

mn102_blsx = _ida_allins.mn102_blsx

mn102_blt = _ida_allins.mn102_blt

mn102_bltx = _ida_allins.mn102_bltx

mn102_bnc = _ida_allins.mn102_bnc

mn102_bncx = _ida_allins.mn102_bncx

mn102_bne = _ida_allins.mn102_bne

mn102_bnex = _ida_allins.mn102_bnex

mn102_bns = _ida_allins.mn102_bns

mn102_bnsx = _ida_allins.mn102_bnsx

mn102_bra = _ida_allins.mn102_bra

mn102_bset = _ida_allins.mn102_bset

mn102_btst = _ida_allins.mn102_btst

mn102_bvc = _ida_allins.mn102_bvc

mn102_bvcx = _ida_allins.mn102_bvcx

mn102_bvs = _ida_allins.mn102_bvs

mn102_bvsx = _ida_allins.mn102_bvsx

mn102_cmp = _ida_allins.mn102_cmp

mn102_divu = _ida_allins.mn102_divu

mn102_ext = _ida_allins.mn102_ext

mn102_extx = _ida_allins.mn102_extx

mn102_extxb = _ida_allins.mn102_extxb

mn102_extxbu = _ida_allins.mn102_extxbu

mn102_extxu = _ida_allins.mn102_extxu

mn102_jmp = _ida_allins.mn102_jmp

mn102_jsr = _ida_allins.mn102_jsr

mn102_lsr = _ida_allins.mn102_lsr

mn102_mov = _ida_allins.mn102_mov

mn102_movb = _ida_allins.mn102_movb

mn102_movbu = _ida_allins.mn102_movbu

mn102_movx = _ida_allins.mn102_movx

mn102_mul = _ida_allins.mn102_mul

mn102_mulq = _ida_allins.mn102_mulq

mn102_mulqh = _ida_allins.mn102_mulqh

mn102_mulql = _ida_allins.mn102_mulql

mn102_mulu = _ida_allins.mn102_mulu

mn102_nop = _ida_allins.mn102_nop

mn102_not = _ida_allins.mn102_not

mn102_or = _ida_allins.mn102_or

mn102_pxst = _ida_allins.mn102_pxst

mn102_rol = _ida_allins.mn102_rol

mn102_ror = _ida_allins.mn102_ror

mn102_rti = _ida_allins.mn102_rti

mn102_rts = _ida_allins.mn102_rts

mn102_sub = _ida_allins.mn102_sub

mn102_subc = _ida_allins.mn102_subc

mn102_tbnz = _ida_allins.mn102_tbnz

mn102_tbz = _ida_allins.mn102_tbz

mn102_xor = _ida_allins.mn102_xor

mn102_last = _ida_allins.mn102_last

PPC_null = _ida_allins.PPC_null

PPC_add = _ida_allins.PPC_add

PPC_addc = _ida_allins.PPC_addc

PPC_adde = _ida_allins.PPC_adde

PPC_addi = _ida_allins.PPC_addi

PPC_addic = _ida_allins.PPC_addic

PPC_addis = _ida_allins.PPC_addis

PPC_addme = _ida_allins.PPC_addme

PPC_addze = _ida_allins.PPC_addze

PPC_and = _ida_allins.PPC_and

PPC_andc = _ida_allins.PPC_andc

PPC_andi = _ida_allins.PPC_andi

PPC_andis = _ida_allins.PPC_andis

PPC_b = _ida_allins.PPC_b

PPC_bc = _ida_allins.PPC_bc

PPC_bcctr = _ida_allins.PPC_bcctr

PPC_bclr = _ida_allins.PPC_bclr

PPC_cmp = _ida_allins.PPC_cmp

PPC_cmpi = _ida_allins.PPC_cmpi

PPC_cmpl = _ida_allins.PPC_cmpl

PPC_cmpli = _ida_allins.PPC_cmpli

PPC_cntlzd = _ida_allins.PPC_cntlzd

PPC_cntlzw = _ida_allins.PPC_cntlzw

PPC_crand = _ida_allins.PPC_crand

PPC_crandc = _ida_allins.PPC_crandc

PPC_creqv = _ida_allins.PPC_creqv

PPC_crnand = _ida_allins.PPC_crnand

PPC_crnor = _ida_allins.PPC_crnor

PPC_cror = _ida_allins.PPC_cror

PPC_crorc = _ida_allins.PPC_crorc

PPC_crxor = _ida_allins.PPC_crxor

PPC_dcba = _ida_allins.PPC_dcba

PPC_dcbf = _ida_allins.PPC_dcbf

PPC_dcbi = _ida_allins.PPC_dcbi

PPC_dcbst = _ida_allins.PPC_dcbst

PPC_dcbt = _ida_allins.PPC_dcbt

PPC_dcbtst = _ida_allins.PPC_dcbtst

PPC_dcbz = _ida_allins.PPC_dcbz

PPC_divd = _ida_allins.PPC_divd

PPC_divdu = _ida_allins.PPC_divdu

PPC_divw = _ida_allins.PPC_divw

PPC_divwu = _ida_allins.PPC_divwu

PPC_eciwx = _ida_allins.PPC_eciwx

PPC_ecowx = _ida_allins.PPC_ecowx

PPC_eieio = _ida_allins.PPC_eieio

PPC_eqv = _ida_allins.PPC_eqv

PPC_extsb = _ida_allins.PPC_extsb

PPC_extsh = _ida_allins.PPC_extsh

PPC_extsw = _ida_allins.PPC_extsw

PPC_fabs = _ida_allins.PPC_fabs

PPC_fadd = _ida_allins.PPC_fadd

PPC_fadds = _ida_allins.PPC_fadds

PPC_fcfid = _ida_allins.PPC_fcfid

PPC_fcmpo = _ida_allins.PPC_fcmpo

PPC_fcmpu = _ida_allins.PPC_fcmpu

PPC_fctid = _ida_allins.PPC_fctid

PPC_fctidz = _ida_allins.PPC_fctidz

PPC_fctiw = _ida_allins.PPC_fctiw

PPC_fctiwz = _ida_allins.PPC_fctiwz

PPC_fdiv = _ida_allins.PPC_fdiv

PPC_fdivs = _ida_allins.PPC_fdivs

PPC_fmadd = _ida_allins.PPC_fmadd

PPC_fmadds = _ida_allins.PPC_fmadds

PPC_fmr = _ida_allins.PPC_fmr

PPC_fmsub = _ida_allins.PPC_fmsub

PPC_fmsubs = _ida_allins.PPC_fmsubs

PPC_fmul = _ida_allins.PPC_fmul

PPC_fmuls = _ida_allins.PPC_fmuls

PPC_fnabs = _ida_allins.PPC_fnabs

PPC_fneg = _ida_allins.PPC_fneg

PPC_fnmadd = _ida_allins.PPC_fnmadd

PPC_fnmadds = _ida_allins.PPC_fnmadds

PPC_fnmsub = _ida_allins.PPC_fnmsub

PPC_fnmsubs = _ida_allins.PPC_fnmsubs

PPC_fres = _ida_allins.PPC_fres

PPC_frsp = _ida_allins.PPC_frsp

PPC_frsqrte = _ida_allins.PPC_frsqrte

PPC_fsel = _ida_allins.PPC_fsel

PPC_fsqrt = _ida_allins.PPC_fsqrt

PPC_fsqrts = _ida_allins.PPC_fsqrts

PPC_fsub = _ida_allins.PPC_fsub

PPC_fsubs = _ida_allins.PPC_fsubs

PPC_icbi = _ida_allins.PPC_icbi

PPC_isync = _ida_allins.PPC_isync

PPC_lbz = _ida_allins.PPC_lbz

PPC_lbzu = _ida_allins.PPC_lbzu

PPC_lbzux = _ida_allins.PPC_lbzux

PPC_lbzx = _ida_allins.PPC_lbzx

PPC_ld = _ida_allins.PPC_ld

PPC_ldarx = _ida_allins.PPC_ldarx

PPC_ldu = _ida_allins.PPC_ldu

PPC_ldux = _ida_allins.PPC_ldux

PPC_ldx = _ida_allins.PPC_ldx

PPC_lfd = _ida_allins.PPC_lfd

PPC_lfdu = _ida_allins.PPC_lfdu

PPC_lfdux = _ida_allins.PPC_lfdux

PPC_lfdx = _ida_allins.PPC_lfdx

PPC_lfs = _ida_allins.PPC_lfs

PPC_lfsu = _ida_allins.PPC_lfsu

PPC_lfsux = _ida_allins.PPC_lfsux

PPC_lfsx = _ida_allins.PPC_lfsx

PPC_lha = _ida_allins.PPC_lha

PPC_lhau = _ida_allins.PPC_lhau

PPC_lhaux = _ida_allins.PPC_lhaux

PPC_lhax = _ida_allins.PPC_lhax

PPC_lhbrx = _ida_allins.PPC_lhbrx

PPC_lhz = _ida_allins.PPC_lhz

PPC_lhzu = _ida_allins.PPC_lhzu

PPC_lhzux = _ida_allins.PPC_lhzux

PPC_lhzx = _ida_allins.PPC_lhzx

PPC_lmw = _ida_allins.PPC_lmw

PPC_lswi = _ida_allins.PPC_lswi

PPC_lswx = _ida_allins.PPC_lswx

PPC_lwa = _ida_allins.PPC_lwa

PPC_lwarx = _ida_allins.PPC_lwarx

PPC_lwaux = _ida_allins.PPC_lwaux

PPC_lwax = _ida_allins.PPC_lwax

PPC_lwbrx = _ida_allins.PPC_lwbrx

PPC_lwz = _ida_allins.PPC_lwz

PPC_lwzu = _ida_allins.PPC_lwzu

PPC_lwzux = _ida_allins.PPC_lwzux

PPC_lwzx = _ida_allins.PPC_lwzx

PPC_mcrf = _ida_allins.PPC_mcrf

PPC_mcrfs = _ida_allins.PPC_mcrfs

PPC_mcrxr = _ida_allins.PPC_mcrxr

PPC_mfcr = _ida_allins.PPC_mfcr

PPC_mffs = _ida_allins.PPC_mffs

PPC_mfmsr = _ida_allins.PPC_mfmsr

PPC_mfspr = _ida_allins.PPC_mfspr

PPC_mfsr = _ida_allins.PPC_mfsr

PPC_mfsrin = _ida_allins.PPC_mfsrin

PPC_mftb = _ida_allins.PPC_mftb

PPC_mtcrf = _ida_allins.PPC_mtcrf

PPC_mtfsb0 = _ida_allins.PPC_mtfsb0

PPC_mtfsb1 = _ida_allins.PPC_mtfsb1

PPC_mtfsf = _ida_allins.PPC_mtfsf

PPC_mtfsfi = _ida_allins.PPC_mtfsfi

PPC_mtmsr = _ida_allins.PPC_mtmsr

PPC_mtmsrd = _ida_allins.PPC_mtmsrd

PPC_mtspr = _ida_allins.PPC_mtspr

PPC_mtsr = _ida_allins.PPC_mtsr

PPC_mtsrd = _ida_allins.PPC_mtsrd

PPC_mtsrdin = _ida_allins.PPC_mtsrdin

PPC_mtsrin = _ida_allins.PPC_mtsrin

PPC_mulhd = _ida_allins.PPC_mulhd

PPC_mulhdu = _ida_allins.PPC_mulhdu

PPC_mulhw = _ida_allins.PPC_mulhw

PPC_mulhwu = _ida_allins.PPC_mulhwu

PPC_mulld = _ida_allins.PPC_mulld

PPC_mulli = _ida_allins.PPC_mulli

PPC_mullw = _ida_allins.PPC_mullw

PPC_nand = _ida_allins.PPC_nand

PPC_neg = _ida_allins.PPC_neg

PPC_nor = _ida_allins.PPC_nor

PPC_or = _ida_allins.PPC_or

PPC_orc = _ida_allins.PPC_orc

PPC_ori = _ida_allins.PPC_ori

PPC_oris = _ida_allins.PPC_oris

PPC_rfi = _ida_allins.PPC_rfi

PPC_rfid = _ida_allins.PPC_rfid

PPC_rldcl = _ida_allins.PPC_rldcl

PPC_rldcr = _ida_allins.PPC_rldcr

PPC_rldic = _ida_allins.PPC_rldic

PPC_rldicl = _ida_allins.PPC_rldicl

PPC_rldicr = _ida_allins.PPC_rldicr

PPC_rldimi = _ida_allins.PPC_rldimi

PPC_rlwimi = _ida_allins.PPC_rlwimi

PPC_rlwinm = _ida_allins.PPC_rlwinm

PPC_rlwnm = _ida_allins.PPC_rlwnm

PPC_sc = _ida_allins.PPC_sc

PPC_slbia = _ida_allins.PPC_slbia

PPC_slbie = _ida_allins.PPC_slbie

PPC_sld = _ida_allins.PPC_sld

PPC_slw = _ida_allins.PPC_slw

PPC_srad = _ida_allins.PPC_srad

PPC_sradi = _ida_allins.PPC_sradi

PPC_sraw = _ida_allins.PPC_sraw

PPC_srawi = _ida_allins.PPC_srawi

PPC_srd = _ida_allins.PPC_srd

PPC_srw = _ida_allins.PPC_srw

PPC_stb = _ida_allins.PPC_stb

PPC_stbu = _ida_allins.PPC_stbu

PPC_stbux = _ida_allins.PPC_stbux

PPC_stbx = _ida_allins.PPC_stbx

PPC_std = _ida_allins.PPC_std

PPC_stdcx = _ida_allins.PPC_stdcx

PPC_stdu = _ida_allins.PPC_stdu

PPC_stdux = _ida_allins.PPC_stdux

PPC_stdx = _ida_allins.PPC_stdx

PPC_stfd = _ida_allins.PPC_stfd

PPC_stfdu = _ida_allins.PPC_stfdu

PPC_stfdux = _ida_allins.PPC_stfdux

PPC_stfdx = _ida_allins.PPC_stfdx

PPC_stfiwx = _ida_allins.PPC_stfiwx

PPC_stfs = _ida_allins.PPC_stfs

PPC_stfsu = _ida_allins.PPC_stfsu

PPC_stfsux = _ida_allins.PPC_stfsux

PPC_stfsx = _ida_allins.PPC_stfsx

PPC_sth = _ida_allins.PPC_sth

PPC_sthbrx = _ida_allins.PPC_sthbrx

PPC_sthu = _ida_allins.PPC_sthu

PPC_sthux = _ida_allins.PPC_sthux

PPC_sthx = _ida_allins.PPC_sthx

PPC_stmw = _ida_allins.PPC_stmw

PPC_stswi = _ida_allins.PPC_stswi

PPC_stswx = _ida_allins.PPC_stswx

PPC_stw = _ida_allins.PPC_stw

PPC_stwbrx = _ida_allins.PPC_stwbrx

PPC_stwcx = _ida_allins.PPC_stwcx

PPC_stwu = _ida_allins.PPC_stwu

PPC_stwux = _ida_allins.PPC_stwux

PPC_stwx = _ida_allins.PPC_stwx

PPC_subf = _ida_allins.PPC_subf

PPC_subfc = _ida_allins.PPC_subfc

PPC_subfe = _ida_allins.PPC_subfe

PPC_subfic = _ida_allins.PPC_subfic

PPC_subfme = _ida_allins.PPC_subfme

PPC_subfze = _ida_allins.PPC_subfze

PPC_sync = _ida_allins.PPC_sync

PPC_td = _ida_allins.PPC_td

PPC_tdi = _ida_allins.PPC_tdi

PPC_tlbia = _ida_allins.PPC_tlbia

PPC_tlbie = _ida_allins.PPC_tlbie

PPC_tlbsync = _ida_allins.PPC_tlbsync

PPC_tw = _ida_allins.PPC_tw

PPC_twi = _ida_allins.PPC_twi

PPC_xor = _ida_allins.PPC_xor

PPC_xori = _ida_allins.PPC_xori

PPC_xoris = _ida_allins.PPC_xoris

PPC_last_basic = _ida_allins.PPC_last_basic

PPC_cmpwi = _ida_allins.PPC_cmpwi

PPC_cmpw = _ida_allins.PPC_cmpw

PPC_cmplwi = _ida_allins.PPC_cmplwi

PPC_cmplw = _ida_allins.PPC_cmplw

PPC_cmpdi = _ida_allins.PPC_cmpdi

PPC_cmpd = _ida_allins.PPC_cmpd

PPC_cmpldi = _ida_allins.PPC_cmpldi

PPC_cmpld = _ida_allins.PPC_cmpld

PPC_trap = _ida_allins.PPC_trap

PPC_trapd = _ida_allins.PPC_trapd

PPC_twlgt = _ida_allins.PPC_twlgt

PPC_twllt = _ida_allins.PPC_twllt

PPC_tweq = _ida_allins.PPC_tweq

PPC_twlge = _ida_allins.PPC_twlge

PPC_twlle = _ida_allins.PPC_twlle

PPC_twgt = _ida_allins.PPC_twgt

PPC_twge = _ida_allins.PPC_twge

PPC_twlt = _ida_allins.PPC_twlt

PPC_twle = _ida_allins.PPC_twle

PPC_twne = _ida_allins.PPC_twne

PPC_twlgti = _ida_allins.PPC_twlgti

PPC_twllti = _ida_allins.PPC_twllti

PPC_tweqi = _ida_allins.PPC_tweqi

PPC_twlgei = _ida_allins.PPC_twlgei

PPC_twllei = _ida_allins.PPC_twllei

PPC_twgti = _ida_allins.PPC_twgti

PPC_twgei = _ida_allins.PPC_twgei

PPC_twlti = _ida_allins.PPC_twlti

PPC_twlei = _ida_allins.PPC_twlei

PPC_twnei = _ida_allins.PPC_twnei

PPC_tdlgt = _ida_allins.PPC_tdlgt

PPC_tdllt = _ida_allins.PPC_tdllt

PPC_tdeq = _ida_allins.PPC_tdeq

PPC_tdlge = _ida_allins.PPC_tdlge

PPC_tdlle = _ida_allins.PPC_tdlle

PPC_tdgt = _ida_allins.PPC_tdgt

PPC_tdge = _ida_allins.PPC_tdge

PPC_tdlt = _ida_allins.PPC_tdlt

PPC_tdle = _ida_allins.PPC_tdle

PPC_tdne = _ida_allins.PPC_tdne

PPC_tdlgti = _ida_allins.PPC_tdlgti

PPC_tdllti = _ida_allins.PPC_tdllti

PPC_tdeqi = _ida_allins.PPC_tdeqi

PPC_tdlgei = _ida_allins.PPC_tdlgei

PPC_tdllei = _ida_allins.PPC_tdllei

PPC_tdgti = _ida_allins.PPC_tdgti

PPC_tdgei = _ida_allins.PPC_tdgei

PPC_tdlti = _ida_allins.PPC_tdlti

PPC_tdlei = _ida_allins.PPC_tdlei

PPC_tdnei = _ida_allins.PPC_tdnei

PPC_nop = _ida_allins.PPC_nop

PPC_not = _ida_allins.PPC_not

PPC_mr = _ida_allins.PPC_mr

PPC_subi = _ida_allins.PPC_subi

PPC_subic = _ida_allins.PPC_subic

PPC_subis = _ida_allins.PPC_subis

PPC_li = _ida_allins.PPC_li

PPC_lis = _ida_allins.PPC_lis

PPC_crset = _ida_allins.PPC_crset

PPC_crnot = _ida_allins.PPC_crnot

PPC_crmove = _ida_allins.PPC_crmove

PPC_crclr = _ida_allins.PPC_crclr

PPC_mtxer = _ida_allins.PPC_mtxer

PPC_mtlr = _ida_allins.PPC_mtlr

PPC_mtctr = _ida_allins.PPC_mtctr

PPC_mtdsisr = _ida_allins.PPC_mtdsisr

PPC_mtdar = _ida_allins.PPC_mtdar

PPC_mtdec = _ida_allins.PPC_mtdec

PPC_mtsrr0 = _ida_allins.PPC_mtsrr0

PPC_mtsrr1 = _ida_allins.PPC_mtsrr1

PPC_mtsprg0 = _ida_allins.PPC_mtsprg0

PPC_mtsprg1 = _ida_allins.PPC_mtsprg1

PPC_mtsprg2 = _ida_allins.PPC_mtsprg2

PPC_mtsprg3 = _ida_allins.PPC_mtsprg3

PPC_mttbl = _ida_allins.PPC_mttbl

PPC_mttbu = _ida_allins.PPC_mttbu

PPC_mfxer = _ida_allins.PPC_mfxer

PPC_mflr = _ida_allins.PPC_mflr

PPC_mfctr = _ida_allins.PPC_mfctr

PPC_mfdsisr = _ida_allins.PPC_mfdsisr

PPC_mfdar = _ida_allins.PPC_mfdar

PPC_mfdec = _ida_allins.PPC_mfdec

PPC_mfsrr0 = _ida_allins.PPC_mfsrr0

PPC_mfsrr1 = _ida_allins.PPC_mfsrr1

PPC_mfsprg0 = _ida_allins.PPC_mfsprg0

PPC_mfsprg1 = _ida_allins.PPC_mfsprg1

PPC_mfsprg2 = _ida_allins.PPC_mfsprg2

PPC_mfsprg3 = _ida_allins.PPC_mfsprg3

PPC_mftbl = _ida_allins.PPC_mftbl

PPC_mftbu = _ida_allins.PPC_mftbu

PPC_mfpvr = _ida_allins.PPC_mfpvr

PPC_balways = _ida_allins.PPC_balways

PPC_bt = _ida_allins.PPC_bt

PPC_bf = _ida_allins.PPC_bf

PPC_bdnz = _ida_allins.PPC_bdnz

PPC_bdnzt = _ida_allins.PPC_bdnzt

PPC_bdnzf = _ida_allins.PPC_bdnzf

PPC_bdz = _ida_allins.PPC_bdz

PPC_bdzt = _ida_allins.PPC_bdzt

PPC_bdzf = _ida_allins.PPC_bdzf

PPC_blt = _ida_allins.PPC_blt

PPC_ble = _ida_allins.PPC_ble

PPC_beq = _ida_allins.PPC_beq

PPC_bge = _ida_allins.PPC_bge

PPC_bgt = _ida_allins.PPC_bgt

PPC_bne = _ida_allins.PPC_bne

PPC_bso = _ida_allins.PPC_bso

PPC_bns = _ida_allins.PPC_bns

PPC_extlwi = _ida_allins.PPC_extlwi

PPC_extrwi = _ida_allins.PPC_extrwi

PPC_inslwi = _ida_allins.PPC_inslwi

PPC_insrwi = _ida_allins.PPC_insrwi

PPC_rotlwi = _ida_allins.PPC_rotlwi

PPC_rotrwi = _ida_allins.PPC_rotrwi

PPC_rotlw = _ida_allins.PPC_rotlw

PPC_slwi = _ida_allins.PPC_slwi

PPC_srwi = _ida_allins.PPC_srwi

PPC_clrlwi = _ida_allins.PPC_clrlwi

PPC_clrrwi = _ida_allins.PPC_clrrwi

PPC_clrlslwi = _ida_allins.PPC_clrlslwi

PPC_dccci = _ida_allins.PPC_dccci

PPC_dcread = _ida_allins.PPC_dcread

PPC_icbt = _ida_allins.PPC_icbt

PPC_iccci = _ida_allins.PPC_iccci

PPC_icread = _ida_allins.PPC_icread

PPC_mfdcr = _ida_allins.PPC_mfdcr

PPC_mtdcr = _ida_allins.PPC_mtdcr

PPC_rfci = _ida_allins.PPC_rfci

PPC_tlbre = _ida_allins.PPC_tlbre

PPC_tlbsx = _ida_allins.PPC_tlbsx

PPC_tlbwe = _ida_allins.PPC_tlbwe

PPC_wrtee = _ida_allins.PPC_wrtee

PPC_wrteei = _ida_allins.PPC_wrteei

PPC_abs = _ida_allins.PPC_abs

PPC_clcs = _ida_allins.PPC_clcs

PPC_clf = _ida_allins.PPC_clf

PPC_cli = _ida_allins.PPC_cli

PPC_dclst = _ida_allins.PPC_dclst

PPC_div = _ida_allins.PPC_div

PPC_divs = _ida_allins.PPC_divs

PPC_doz = _ida_allins.PPC_doz

PPC_dozi = _ida_allins.PPC_dozi

PPC_frsqrtes = _ida_allins.PPC_frsqrtes

PPC_hrfid = _ida_allins.PPC_hrfid

PPC_lscbx = _ida_allins.PPC_lscbx

PPC_maskg = _ida_allins.PPC_maskg

PPC_maskir = _ida_allins.PPC_maskir

PPC_mfsri = _ida_allins.PPC_mfsri

PPC_mul = _ida_allins.PPC_mul

PPC_nabs = _ida_allins.PPC_nabs

PPC_popcntb = _ida_allins.PPC_popcntb

PPC_rac = _ida_allins.PPC_rac

PPC_rfsvc = _ida_allins.PPC_rfsvc

PPC_rlmi = _ida_allins.PPC_rlmi

PPC_rrib = _ida_allins.PPC_rrib

PPC_slbmfee = _ida_allins.PPC_slbmfee

PPC_slbmfev = _ida_allins.PPC_slbmfev

PPC_slbmte = _ida_allins.PPC_slbmte

PPC_sle = _ida_allins.PPC_sle

PPC_sleq = _ida_allins.PPC_sleq

PPC_sliq = _ida_allins.PPC_sliq

PPC_slliq = _ida_allins.PPC_slliq

PPC_sllq = _ida_allins.PPC_sllq

PPC_slq = _ida_allins.PPC_slq

PPC_sraiq = _ida_allins.PPC_sraiq

PPC_sraq = _ida_allins.PPC_sraq

PPC_sre = _ida_allins.PPC_sre

PPC_srea = _ida_allins.PPC_srea

PPC_sreq = _ida_allins.PPC_sreq

PPC_sriq = _ida_allins.PPC_sriq

PPC_srliq = _ida_allins.PPC_srliq

PPC_srlq = _ida_allins.PPC_srlq

PPC_srq = _ida_allins.PPC_srq

PPC_mtocrf = _ida_allins.PPC_mtocrf

PPC_mfocrf = _ida_allins.PPC_mfocrf

PPC_isel = _ida_allins.PPC_isel

PPC_isellt = _ida_allins.PPC_isellt

PPC_iselgt = _ida_allins.PPC_iselgt

PPC_iseleq = _ida_allins.PPC_iseleq

PPC_dcblc = _ida_allins.PPC_dcblc

PPC_dcbtls = _ida_allins.PPC_dcbtls

PPC_dcbtstls = _ida_allins.PPC_dcbtstls

PPC_icblc = _ida_allins.PPC_icblc

PPC_icbtls = _ida_allins.PPC_icbtls

PPC_tlbivax = _ida_allins.PPC_tlbivax

PPC_rfdi = _ida_allins.PPC_rfdi

PPC_tlbld = _ida_allins.PPC_tlbld

PPC_tlbli = _ida_allins.PPC_tlbli

PPC_brinc = _ida_allins.PPC_brinc

PPC_evabs = _ida_allins.PPC_evabs

PPC_evaddiw = _ida_allins.PPC_evaddiw

PPC_evaddsmiaaw = _ida_allins.PPC_evaddsmiaaw

PPC_evaddssiaaw = _ida_allins.PPC_evaddssiaaw

PPC_evaddumiaaw = _ida_allins.PPC_evaddumiaaw

PPC_evaddusiaaw = _ida_allins.PPC_evaddusiaaw

PPC_evaddw = _ida_allins.PPC_evaddw

PPC_evand = _ida_allins.PPC_evand

PPC_evandc = _ida_allins.PPC_evandc

PPC_evcmpeq = _ida_allins.PPC_evcmpeq

PPC_evcmpgts = _ida_allins.PPC_evcmpgts

PPC_evcmpgtu = _ida_allins.PPC_evcmpgtu

PPC_evcmplts = _ida_allins.PPC_evcmplts

PPC_evcmpltu = _ida_allins.PPC_evcmpltu

PPC_evcntlsw = _ida_allins.PPC_evcntlsw

PPC_evcntlzw = _ida_allins.PPC_evcntlzw

PPC_evdivws = _ida_allins.PPC_evdivws

PPC_evdivwu = _ida_allins.PPC_evdivwu

PPC_eveqv = _ida_allins.PPC_eveqv

PPC_evextsb = _ida_allins.PPC_evextsb

PPC_evextsh = _ida_allins.PPC_evextsh

PPC_evldd = _ida_allins.PPC_evldd

PPC_evlddx = _ida_allins.PPC_evlddx

PPC_evldh = _ida_allins.PPC_evldh

PPC_evldhx = _ida_allins.PPC_evldhx

PPC_evldw = _ida_allins.PPC_evldw

PPC_evldwx = _ida_allins.PPC_evldwx

PPC_evlhhesplat = _ida_allins.PPC_evlhhesplat

PPC_evlhhesplatx = _ida_allins.PPC_evlhhesplatx

PPC_evlhhossplat = _ida_allins.PPC_evlhhossplat

PPC_evlhhossplatx = _ida_allins.PPC_evlhhossplatx

PPC_evlhhousplat = _ida_allins.PPC_evlhhousplat

PPC_evlhhousplatx = _ida_allins.PPC_evlhhousplatx

PPC_evlwhe = _ida_allins.PPC_evlwhe

PPC_evlwhex = _ida_allins.PPC_evlwhex

PPC_evlwhos = _ida_allins.PPC_evlwhos

PPC_evlwhosx = _ida_allins.PPC_evlwhosx

PPC_evlwhou = _ida_allins.PPC_evlwhou

PPC_evlwhoux = _ida_allins.PPC_evlwhoux

PPC_evlwhsplat = _ida_allins.PPC_evlwhsplat

PPC_evlwhsplatx = _ida_allins.PPC_evlwhsplatx

PPC_evlwwsplat = _ida_allins.PPC_evlwwsplat

PPC_evlwwsplatx = _ida_allins.PPC_evlwwsplatx

PPC_evmergehi = _ida_allins.PPC_evmergehi

PPC_evmergehilo = _ida_allins.PPC_evmergehilo

PPC_evmergelo = _ida_allins.PPC_evmergelo

PPC_evmergelohi = _ida_allins.PPC_evmergelohi

PPC_evmhegsmfaa = _ida_allins.PPC_evmhegsmfaa

PPC_evmhegsmfan = _ida_allins.PPC_evmhegsmfan

PPC_evmhegsmiaa = _ida_allins.PPC_evmhegsmiaa

PPC_evmhegsmian = _ida_allins.PPC_evmhegsmian

PPC_evmhegumiaa = _ida_allins.PPC_evmhegumiaa

PPC_evmhegumian = _ida_allins.PPC_evmhegumian

PPC_evmhesmf = _ida_allins.PPC_evmhesmf

PPC_evmhesmfa = _ida_allins.PPC_evmhesmfa

PPC_evmhesmfaaw = _ida_allins.PPC_evmhesmfaaw

PPC_evmhesmfanw = _ida_allins.PPC_evmhesmfanw

PPC_evmhesmi = _ida_allins.PPC_evmhesmi

PPC_evmhesmia = _ida_allins.PPC_evmhesmia

PPC_evmhesmiaaw = _ida_allins.PPC_evmhesmiaaw

PPC_evmhesmianw = _ida_allins.PPC_evmhesmianw

PPC_evmhessf = _ida_allins.PPC_evmhessf

PPC_evmhessfa = _ida_allins.PPC_evmhessfa

PPC_evmhessfaaw = _ida_allins.PPC_evmhessfaaw

PPC_evmhessfanw = _ida_allins.PPC_evmhessfanw

PPC_evmhessiaaw = _ida_allins.PPC_evmhessiaaw

PPC_evmhessianw = _ida_allins.PPC_evmhessianw

PPC_evmheumi = _ida_allins.PPC_evmheumi

PPC_evmheumia = _ida_allins.PPC_evmheumia

PPC_evmheumiaaw = _ida_allins.PPC_evmheumiaaw

PPC_evmheumianw = _ida_allins.PPC_evmheumianw

PPC_evmheusiaaw = _ida_allins.PPC_evmheusiaaw

PPC_evmheusianw = _ida_allins.PPC_evmheusianw

PPC_evmhogsmfaa = _ida_allins.PPC_evmhogsmfaa

PPC_evmhogsmfan = _ida_allins.PPC_evmhogsmfan

PPC_evmhogsmiaa = _ida_allins.PPC_evmhogsmiaa

PPC_evmhogsmian = _ida_allins.PPC_evmhogsmian

PPC_evmhogumiaa = _ida_allins.PPC_evmhogumiaa

PPC_evmhogumian = _ida_allins.PPC_evmhogumian

PPC_evmhosmf = _ida_allins.PPC_evmhosmf

PPC_evmhosmfa = _ida_allins.PPC_evmhosmfa

PPC_evmhosmfaaw = _ida_allins.PPC_evmhosmfaaw

PPC_evmhosmfanw = _ida_allins.PPC_evmhosmfanw

PPC_evmhosmi = _ida_allins.PPC_evmhosmi

PPC_evmhosmia = _ida_allins.PPC_evmhosmia

PPC_evmhosmiaaw = _ida_allins.PPC_evmhosmiaaw

PPC_evmhosmianw = _ida_allins.PPC_evmhosmianw

PPC_evmhossf = _ida_allins.PPC_evmhossf

PPC_evmhossfa = _ida_allins.PPC_evmhossfa

PPC_evmhossfaaw = _ida_allins.PPC_evmhossfaaw

PPC_evmhossfanw = _ida_allins.PPC_evmhossfanw

PPC_evmhossiaaw = _ida_allins.PPC_evmhossiaaw

PPC_evmhossianw = _ida_allins.PPC_evmhossianw

PPC_evmhoumi = _ida_allins.PPC_evmhoumi

PPC_evmhoumia = _ida_allins.PPC_evmhoumia

PPC_evmhoumiaaw = _ida_allins.PPC_evmhoumiaaw

PPC_evmhoumianw = _ida_allins.PPC_evmhoumianw

PPC_evmhousiaaw = _ida_allins.PPC_evmhousiaaw

PPC_evmhousianw = _ida_allins.PPC_evmhousianw

PPC_evmra = _ida_allins.PPC_evmra

PPC_evmwhsmf = _ida_allins.PPC_evmwhsmf

PPC_evmwhsmfa = _ida_allins.PPC_evmwhsmfa

PPC_evmwhsmi = _ida_allins.PPC_evmwhsmi

PPC_evmwhsmia = _ida_allins.PPC_evmwhsmia

PPC_evmwhssf = _ida_allins.PPC_evmwhssf

PPC_evmwhssfa = _ida_allins.PPC_evmwhssfa

PPC_evmwhumi = _ida_allins.PPC_evmwhumi

PPC_evmwhumia = _ida_allins.PPC_evmwhumia

PPC_evmwlsmiaaw = _ida_allins.PPC_evmwlsmiaaw

PPC_evmwlsmianw = _ida_allins.PPC_evmwlsmianw

PPC_evmwlssiaaw = _ida_allins.PPC_evmwlssiaaw

PPC_evmwlssianw = _ida_allins.PPC_evmwlssianw

PPC_evmwlumi = _ida_allins.PPC_evmwlumi

PPC_evmwlumia = _ida_allins.PPC_evmwlumia

PPC_evmwlumiaaw = _ida_allins.PPC_evmwlumiaaw

PPC_evmwlumianw = _ida_allins.PPC_evmwlumianw

PPC_evmwlusiaaw = _ida_allins.PPC_evmwlusiaaw

PPC_evmwlusianw = _ida_allins.PPC_evmwlusianw

PPC_evmwsmf = _ida_allins.PPC_evmwsmf

PPC_evmwsmfa = _ida_allins.PPC_evmwsmfa

PPC_evmwsmfaa = _ida_allins.PPC_evmwsmfaa

PPC_evmwsmfan = _ida_allins.PPC_evmwsmfan

PPC_evmwsmi = _ida_allins.PPC_evmwsmi

PPC_evmwsmia = _ida_allins.PPC_evmwsmia

PPC_evmwsmiaa = _ida_allins.PPC_evmwsmiaa

PPC_evmwsmian = _ida_allins.PPC_evmwsmian

PPC_evmwssf = _ida_allins.PPC_evmwssf

PPC_evmwssfa = _ida_allins.PPC_evmwssfa

PPC_evmwssfaa = _ida_allins.PPC_evmwssfaa

PPC_evmwssfan = _ida_allins.PPC_evmwssfan

PPC_evmwumi = _ida_allins.PPC_evmwumi

PPC_evmwumia = _ida_allins.PPC_evmwumia

PPC_evmwumiaa = _ida_allins.PPC_evmwumiaa

PPC_evmwumian = _ida_allins.PPC_evmwumian

PPC_evnand = _ida_allins.PPC_evnand

PPC_evneg = _ida_allins.PPC_evneg

PPC_evnor = _ida_allins.PPC_evnor

PPC_evor = _ida_allins.PPC_evor

PPC_evorc = _ida_allins.PPC_evorc

PPC_evrlw = _ida_allins.PPC_evrlw

PPC_evrlwi = _ida_allins.PPC_evrlwi

PPC_evrndw = _ida_allins.PPC_evrndw

PPC_evsel = _ida_allins.PPC_evsel

PPC_evslw = _ida_allins.PPC_evslw

PPC_evslwi = _ida_allins.PPC_evslwi

PPC_evsplatfi = _ida_allins.PPC_evsplatfi

PPC_evsplati = _ida_allins.PPC_evsplati

PPC_evsrwis = _ida_allins.PPC_evsrwis

PPC_evsrwiu = _ida_allins.PPC_evsrwiu

PPC_evsrws = _ida_allins.PPC_evsrws

PPC_evsrwu = _ida_allins.PPC_evsrwu

PPC_evstdd = _ida_allins.PPC_evstdd

PPC_evstddx = _ida_allins.PPC_evstddx

PPC_evstdh = _ida_allins.PPC_evstdh

PPC_evstdhx = _ida_allins.PPC_evstdhx

PPC_evstdw = _ida_allins.PPC_evstdw

PPC_evstdwx = _ida_allins.PPC_evstdwx

PPC_evstwhe = _ida_allins.PPC_evstwhe

PPC_evstwhex = _ida_allins.PPC_evstwhex

PPC_evstwho = _ida_allins.PPC_evstwho

PPC_evstwhox = _ida_allins.PPC_evstwhox

PPC_evstwwe = _ida_allins.PPC_evstwwe

PPC_evstwwex = _ida_allins.PPC_evstwwex

PPC_evstwwo = _ida_allins.PPC_evstwwo

PPC_evstwwox = _ida_allins.PPC_evstwwox

PPC_evsubfsmiaaw = _ida_allins.PPC_evsubfsmiaaw

PPC_evsubfssiaaw = _ida_allins.PPC_evsubfssiaaw

PPC_evsubfumiaaw = _ida_allins.PPC_evsubfumiaaw

PPC_evsubfusiaaw = _ida_allins.PPC_evsubfusiaaw

PPC_evsubfw = _ida_allins.PPC_evsubfw

PPC_evsubifw = _ida_allins.PPC_evsubifw

PPC_evxor = _ida_allins.PPC_evxor

PPC_efdabs = _ida_allins.PPC_efdabs

PPC_efdadd = _ida_allins.PPC_efdadd

PPC_efdcfs = _ida_allins.PPC_efdcfs

PPC_efdcfsf = _ida_allins.PPC_efdcfsf

PPC_efdcfsi = _ida_allins.PPC_efdcfsi

PPC_efdcfsid = _ida_allins.PPC_efdcfsid

PPC_efdcfuf = _ida_allins.PPC_efdcfuf

PPC_efdcfui = _ida_allins.PPC_efdcfui

PPC_efdcfuid = _ida_allins.PPC_efdcfuid

PPC_efdcmpeq = _ida_allins.PPC_efdcmpeq

PPC_efdcmpgt = _ida_allins.PPC_efdcmpgt

PPC_efdcmplt = _ida_allins.PPC_efdcmplt

PPC_efdctsf = _ida_allins.PPC_efdctsf

PPC_efdctsi = _ida_allins.PPC_efdctsi

PPC_efdctsidz = _ida_allins.PPC_efdctsidz

PPC_efdctsiz = _ida_allins.PPC_efdctsiz

PPC_efdctuf = _ida_allins.PPC_efdctuf

PPC_efdctui = _ida_allins.PPC_efdctui

PPC_efdctuidz = _ida_allins.PPC_efdctuidz

PPC_efdctuiz = _ida_allins.PPC_efdctuiz

PPC_efddiv = _ida_allins.PPC_efddiv

PPC_efdmul = _ida_allins.PPC_efdmul

PPC_efdnabs = _ida_allins.PPC_efdnabs

PPC_efdneg = _ida_allins.PPC_efdneg

PPC_efdsub = _ida_allins.PPC_efdsub

PPC_efdtsteq = _ida_allins.PPC_efdtsteq

PPC_efdtstgt = _ida_allins.PPC_efdtstgt

PPC_efdtstlt = _ida_allins.PPC_efdtstlt

PPC_efscfd = _ida_allins.PPC_efscfd

PPC_efsabs = _ida_allins.PPC_efsabs

PPC_efsadd = _ida_allins.PPC_efsadd

PPC_efscfsf = _ida_allins.PPC_efscfsf

PPC_efscfsi = _ida_allins.PPC_efscfsi

PPC_efscfuf = _ida_allins.PPC_efscfuf

PPC_efscfui = _ida_allins.PPC_efscfui

PPC_efscmpeq = _ida_allins.PPC_efscmpeq

PPC_efscmpgt = _ida_allins.PPC_efscmpgt

PPC_efscmplt = _ida_allins.PPC_efscmplt

PPC_efsctsf = _ida_allins.PPC_efsctsf

PPC_efsctsi = _ida_allins.PPC_efsctsi

PPC_efsctsiz = _ida_allins.PPC_efsctsiz

PPC_efsctuf = _ida_allins.PPC_efsctuf

PPC_efsctui = _ida_allins.PPC_efsctui

PPC_efsctuiz = _ida_allins.PPC_efsctuiz

PPC_efsdiv = _ida_allins.PPC_efsdiv

PPC_efsmul = _ida_allins.PPC_efsmul

PPC_efsnabs = _ida_allins.PPC_efsnabs

PPC_efsneg = _ida_allins.PPC_efsneg

PPC_efssub = _ida_allins.PPC_efssub

PPC_efststeq = _ida_allins.PPC_efststeq

PPC_efststgt = _ida_allins.PPC_efststgt

PPC_efststlt = _ida_allins.PPC_efststlt

PPC_evfsabs = _ida_allins.PPC_evfsabs

PPC_evfsadd = _ida_allins.PPC_evfsadd

PPC_evfscfsf = _ida_allins.PPC_evfscfsf

PPC_evfscfsi = _ida_allins.PPC_evfscfsi

PPC_evfscfuf = _ida_allins.PPC_evfscfuf

PPC_evfscfui = _ida_allins.PPC_evfscfui

PPC_evfscmpeq = _ida_allins.PPC_evfscmpeq

PPC_evfscmpgt = _ida_allins.PPC_evfscmpgt

PPC_evfscmplt = _ida_allins.PPC_evfscmplt

PPC_evfsctsf = _ida_allins.PPC_evfsctsf

PPC_evfsctsi = _ida_allins.PPC_evfsctsi

PPC_evfsctsiz = _ida_allins.PPC_evfsctsiz

PPC_evfsctuf = _ida_allins.PPC_evfsctuf

PPC_evfsctui = _ida_allins.PPC_evfsctui

PPC_evfsctuiz = _ida_allins.PPC_evfsctuiz

PPC_evfsdiv = _ida_allins.PPC_evfsdiv

PPC_evfsmul = _ida_allins.PPC_evfsmul

PPC_evfsnabs = _ida_allins.PPC_evfsnabs

PPC_evfsneg = _ida_allins.PPC_evfsneg

PPC_evfssub = _ida_allins.PPC_evfssub

PPC_evfststeq = _ida_allins.PPC_evfststeq

PPC_evfststgt = _ida_allins.PPC_evfststgt

PPC_evfststlt = _ida_allins.PPC_evfststlt

PPC_bpermd = _ida_allins.PPC_bpermd

PPC_divde = _ida_allins.PPC_divde

PPC_divdeu = _ida_allins.PPC_divdeu

PPC_ldbrx = _ida_allins.PPC_ldbrx

PPC_prtyd = _ida_allins.PPC_prtyd

PPC_stdbrx = _ida_allins.PPC_stdbrx

PPC_cmpb = _ida_allins.PPC_cmpb

PPC_divwe = _ida_allins.PPC_divwe

PPC_divweu = _ida_allins.PPC_divweu

PPC_lbarx = _ida_allins.PPC_lbarx

PPC_lharx = _ida_allins.PPC_lharx

PPC_popcntd = _ida_allins.PPC_popcntd

PPC_popcntw = _ida_allins.PPC_popcntw

PPC_prtyw = _ida_allins.PPC_prtyw

PPC_stbcx = _ida_allins.PPC_stbcx

PPC_sthcx = _ida_allins.PPC_sthcx

PPC_addg6s = _ida_allins.PPC_addg6s

PPC_cbcdtd = _ida_allins.PPC_cbcdtd

PPC_cdtbcd = _ida_allins.PPC_cdtbcd

PPC_dadd = _ida_allins.PPC_dadd

PPC_daddq = _ida_allins.PPC_daddq

PPC_dcffix = _ida_allins.PPC_dcffix

PPC_dcffixq = _ida_allins.PPC_dcffixq

PPC_dcmpo = _ida_allins.PPC_dcmpo

PPC_dcmpoq = _ida_allins.PPC_dcmpoq

PPC_dcmpu = _ida_allins.PPC_dcmpu

PPC_dcmpuq = _ida_allins.PPC_dcmpuq

PPC_dctdp = _ida_allins.PPC_dctdp

PPC_dctfix = _ida_allins.PPC_dctfix

PPC_dctfixq = _ida_allins.PPC_dctfixq

PPC_dctqpq = _ida_allins.PPC_dctqpq

PPC_ddedpd = _ida_allins.PPC_ddedpd

PPC_ddedpdq = _ida_allins.PPC_ddedpdq

PPC_ddiv = _ida_allins.PPC_ddiv

PPC_ddivq = _ida_allins.PPC_ddivq

PPC_denbcd = _ida_allins.PPC_denbcd

PPC_denbcdq = _ida_allins.PPC_denbcdq

PPC_diex = _ida_allins.PPC_diex

PPC_diexq = _ida_allins.PPC_diexq

PPC_dmul = _ida_allins.PPC_dmul

PPC_dmulq = _ida_allins.PPC_dmulq

PPC_dqua = _ida_allins.PPC_dqua

PPC_dquai = _ida_allins.PPC_dquai

PPC_dquaiq = _ida_allins.PPC_dquaiq

PPC_dquaq = _ida_allins.PPC_dquaq

PPC_drdpq = _ida_allins.PPC_drdpq

PPC_drintn = _ida_allins.PPC_drintn

PPC_drintnq = _ida_allins.PPC_drintnq

PPC_drintx = _ida_allins.PPC_drintx

PPC_drintxq = _ida_allins.PPC_drintxq

PPC_drrnd = _ida_allins.PPC_drrnd

PPC_drrndq = _ida_allins.PPC_drrndq

PPC_drsp = _ida_allins.PPC_drsp

PPC_dscli = _ida_allins.PPC_dscli

PPC_dscliq = _ida_allins.PPC_dscliq

PPC_dscri = _ida_allins.PPC_dscri

PPC_dscriq = _ida_allins.PPC_dscriq

PPC_dsub = _ida_allins.PPC_dsub

PPC_dsubq = _ida_allins.PPC_dsubq

PPC_dtstdc = _ida_allins.PPC_dtstdc

PPC_dtstdcq = _ida_allins.PPC_dtstdcq

PPC_dtstdg = _ida_allins.PPC_dtstdg

PPC_dtstdgq = _ida_allins.PPC_dtstdgq

PPC_dtstex = _ida_allins.PPC_dtstex

PPC_dtstexq = _ida_allins.PPC_dtstexq

PPC_dtstsf = _ida_allins.PPC_dtstsf

PPC_dtstsfq = _ida_allins.PPC_dtstsfq

PPC_dxex = _ida_allins.PPC_dxex

PPC_dxexq = _ida_allins.PPC_dxexq

PPC_dsn = _ida_allins.PPC_dsn

PPC_lbdx = _ida_allins.PPC_lbdx

PPC_lddx = _ida_allins.PPC_lddx

PPC_lfddx = _ida_allins.PPC_lfddx

PPC_lhdx = _ida_allins.PPC_lhdx

PPC_lwdx = _ida_allins.PPC_lwdx

PPC_stbdx = _ida_allins.PPC_stbdx

PPC_stddx = _ida_allins.PPC_stddx

PPC_stfddx = _ida_allins.PPC_stfddx

PPC_sthdx = _ida_allins.PPC_sthdx

PPC_stwdx = _ida_allins.PPC_stwdx

PPC_mbar = _ida_allins.PPC_mbar

PPC_rfmci = _ida_allins.PPC_rfmci

PPC_tlbilx = _ida_allins.PPC_tlbilx

PPC_dci = _ida_allins.PPC_dci

PPC_ici = _ida_allins.PPC_ici

PPC_mfdcrux = _ida_allins.PPC_mfdcrux

PPC_mfdcrx = _ida_allins.PPC_mfdcrx

PPC_mtdcrux = _ida_allins.PPC_mtdcrux

PPC_mtdcrx = _ida_allins.PPC_mtdcrx

PPC_dnh = _ida_allins.PPC_dnh

PPC_ehpriv = _ida_allins.PPC_ehpriv

PPC_rfgi = _ida_allins.PPC_rfgi

PPC_msgclr = _ida_allins.PPC_msgclr

PPC_msgsnd = _ida_allins.PPC_msgsnd

PPC_dcbfep = _ida_allins.PPC_dcbfep

PPC_dcbstep = _ida_allins.PPC_dcbstep

PPC_dcbtep = _ida_allins.PPC_dcbtep

PPC_dcbtstep = _ida_allins.PPC_dcbtstep

PPC_dcbzep = _ida_allins.PPC_dcbzep

PPC_evlddepx = _ida_allins.PPC_evlddepx

PPC_evstddepx = _ida_allins.PPC_evstddepx

PPC_icbiep = _ida_allins.PPC_icbiep

PPC_lbepx = _ida_allins.PPC_lbepx

PPC_lfdepx = _ida_allins.PPC_lfdepx

PPC_lhepx = _ida_allins.PPC_lhepx

PPC_lvepx = _ida_allins.PPC_lvepx

PPC_lvepxl = _ida_allins.PPC_lvepxl

PPC_lwepx = _ida_allins.PPC_lwepx

PPC_stbepx = _ida_allins.PPC_stbepx

PPC_stfdepx = _ida_allins.PPC_stfdepx

PPC_sthepx = _ida_allins.PPC_sthepx

PPC_stvepx = _ida_allins.PPC_stvepx

PPC_stvepxl = _ida_allins.PPC_stvepxl

PPC_stwepx = _ida_allins.PPC_stwepx

PPC_ldepx = _ida_allins.PPC_ldepx

PPC_stdepx = _ida_allins.PPC_stdepx

PPC_mfpmr = _ida_allins.PPC_mfpmr

PPC_mtpmr = _ida_allins.PPC_mtpmr

PPC_mftmr = _ida_allins.PPC_mftmr

PPC_mttmr = _ida_allins.PPC_mttmr

PPC_tlbsrx = _ida_allins.PPC_tlbsrx

PPC_fcfids = _ida_allins.PPC_fcfids

PPC_fcfidu = _ida_allins.PPC_fcfidu

PPC_fcfidus = _ida_allins.PPC_fcfidus

PPC_fctidu = _ida_allins.PPC_fctidu

PPC_fctiduz = _ida_allins.PPC_fctiduz

PPC_fctiwu = _ida_allins.PPC_fctiwu

PPC_fctiwuz = _ida_allins.PPC_fctiwuz

PPC_ftdiv = _ida_allins.PPC_ftdiv

PPC_ftsqrt = _ida_allins.PPC_ftsqrt

PPC_lfiwax = _ida_allins.PPC_lfiwax

PPC_lfiwzx = _ida_allins.PPC_lfiwzx

PPC_lfdp = _ida_allins.PPC_lfdp

PPC_lfdpx = _ida_allins.PPC_lfdpx

PPC_stfdp = _ida_allins.PPC_stfdp

PPC_stfdpx = _ida_allins.PPC_stfdpx

PPC_fcpsgn = _ida_allins.PPC_fcpsgn

PPC_fre = _ida_allins.PPC_fre

PPC_frim = _ida_allins.PPC_frim

PPC_frin = _ida_allins.PPC_frin

PPC_frip = _ida_allins.PPC_frip

PPC_friz = _ida_allins.PPC_friz

PPC_macchw = _ida_allins.PPC_macchw

PPC_macchws = _ida_allins.PPC_macchws

PPC_macchwsu = _ida_allins.PPC_macchwsu

PPC_macchwu = _ida_allins.PPC_macchwu

PPC_machhw = _ida_allins.PPC_machhw

PPC_machhws = _ida_allins.PPC_machhws

PPC_machhwsu = _ida_allins.PPC_machhwsu

PPC_machhwu = _ida_allins.PPC_machhwu

PPC_maclhw = _ida_allins.PPC_maclhw

PPC_maclhws = _ida_allins.PPC_maclhws

PPC_maclhwsu = _ida_allins.PPC_maclhwsu

PPC_maclhwu = _ida_allins.PPC_maclhwu

PPC_mulchw = _ida_allins.PPC_mulchw

PPC_mulchwu = _ida_allins.PPC_mulchwu

PPC_mulhhw = _ida_allins.PPC_mulhhw

PPC_mulhhwu = _ida_allins.PPC_mulhhwu

PPC_mullhw = _ida_allins.PPC_mullhw

PPC_mullhwu = _ida_allins.PPC_mullhwu

PPC_nmacchw = _ida_allins.PPC_nmacchw

PPC_nmacchws = _ida_allins.PPC_nmacchws

PPC_nmachhw = _ida_allins.PPC_nmachhw

PPC_nmachhws = _ida_allins.PPC_nmachhws

PPC_nmaclhw = _ida_allins.PPC_nmaclhw

PPC_nmaclhws = _ida_allins.PPC_nmaclhws

PPC_dlmzb = _ida_allins.PPC_dlmzb

PPC_lq = _ida_allins.PPC_lq

PPC_stq = _ida_allins.PPC_stq

PPC_doze = _ida_allins.PPC_doze

PPC_lbzcix = _ida_allins.PPC_lbzcix

PPC_ldcix = _ida_allins.PPC_ldcix

PPC_lhzcix = _ida_allins.PPC_lhzcix

PPC_lwzcix = _ida_allins.PPC_lwzcix

PPC_nap = _ida_allins.PPC_nap

PPC_rvwinkle = _ida_allins.PPC_rvwinkle

PPC_slbfee = _ida_allins.PPC_slbfee

PPC_sleep = _ida_allins.PPC_sleep

PPC_stbcix = _ida_allins.PPC_stbcix

PPC_stdcix = _ida_allins.PPC_stdcix

PPC_sthcix = _ida_allins.PPC_sthcix

PPC_stwcix = _ida_allins.PPC_stwcix

PPC_tlbiel = _ida_allins.PPC_tlbiel

PPC_lvebx = _ida_allins.PPC_lvebx

PPC_lvehx = _ida_allins.PPC_lvehx

PPC_lvewx = _ida_allins.PPC_lvewx

PPC_lvsl = _ida_allins.PPC_lvsl

PPC_lvsr = _ida_allins.PPC_lvsr

PPC_lvx = _ida_allins.PPC_lvx

PPC_lvxl = _ida_allins.PPC_lvxl

PPC_mfvscr = _ida_allins.PPC_mfvscr

PPC_mtvscr = _ida_allins.PPC_mtvscr

PPC_stvebx = _ida_allins.PPC_stvebx

PPC_stvehx = _ida_allins.PPC_stvehx

PPC_stvewx = _ida_allins.PPC_stvewx

PPC_stvx = _ida_allins.PPC_stvx

PPC_stvxl = _ida_allins.PPC_stvxl

PPC_vaddcuw = _ida_allins.PPC_vaddcuw

PPC_vaddfp = _ida_allins.PPC_vaddfp

PPC_vaddsbs = _ida_allins.PPC_vaddsbs

PPC_vaddshs = _ida_allins.PPC_vaddshs

PPC_vaddsws = _ida_allins.PPC_vaddsws

PPC_vaddubm = _ida_allins.PPC_vaddubm

PPC_vaddubs = _ida_allins.PPC_vaddubs

PPC_vadduhm = _ida_allins.PPC_vadduhm

PPC_vadduhs = _ida_allins.PPC_vadduhs

PPC_vadduwm = _ida_allins.PPC_vadduwm

PPC_vadduws = _ida_allins.PPC_vadduws

PPC_vand = _ida_allins.PPC_vand

PPC_vandc = _ida_allins.PPC_vandc

PPC_vavgsb = _ida_allins.PPC_vavgsb

PPC_vavgsh = _ida_allins.PPC_vavgsh

PPC_vavgsw = _ida_allins.PPC_vavgsw

PPC_vavgub = _ida_allins.PPC_vavgub

PPC_vavguh = _ida_allins.PPC_vavguh

PPC_vavguw = _ida_allins.PPC_vavguw

PPC_vcfsx = _ida_allins.PPC_vcfsx

PPC_vcfux = _ida_allins.PPC_vcfux

PPC_vcmpbfp = _ida_allins.PPC_vcmpbfp

PPC_vcmpeqfp = _ida_allins.PPC_vcmpeqfp

PPC_vcmpequb = _ida_allins.PPC_vcmpequb

PPC_vcmpequh = _ida_allins.PPC_vcmpequh

PPC_vcmpequw = _ida_allins.PPC_vcmpequw

PPC_vcmpgefp = _ida_allins.PPC_vcmpgefp

PPC_vcmpgtfp = _ida_allins.PPC_vcmpgtfp

PPC_vcmpgtsb = _ida_allins.PPC_vcmpgtsb

PPC_vcmpgtsh = _ida_allins.PPC_vcmpgtsh

PPC_vcmpgtsw = _ida_allins.PPC_vcmpgtsw

PPC_vcmpgtub = _ida_allins.PPC_vcmpgtub

PPC_vcmpgtuh = _ida_allins.PPC_vcmpgtuh

PPC_vcmpgtuw = _ida_allins.PPC_vcmpgtuw

PPC_vctsxs = _ida_allins.PPC_vctsxs

PPC_vctuxs = _ida_allins.PPC_vctuxs

PPC_vexptefp = _ida_allins.PPC_vexptefp

PPC_vlogefp = _ida_allins.PPC_vlogefp

PPC_vmaddfp = _ida_allins.PPC_vmaddfp

PPC_vmaxfp = _ida_allins.PPC_vmaxfp

PPC_vmaxsb = _ida_allins.PPC_vmaxsb

PPC_vmaxsh = _ida_allins.PPC_vmaxsh

PPC_vmaxsw = _ida_allins.PPC_vmaxsw

PPC_vmaxub = _ida_allins.PPC_vmaxub

PPC_vmaxuh = _ida_allins.PPC_vmaxuh

PPC_vmaxuw = _ida_allins.PPC_vmaxuw

PPC_vmhaddshs = _ida_allins.PPC_vmhaddshs

PPC_vmhraddshs = _ida_allins.PPC_vmhraddshs

PPC_vminfp = _ida_allins.PPC_vminfp

PPC_vminsb = _ida_allins.PPC_vminsb

PPC_vminsh = _ida_allins.PPC_vminsh

PPC_vminsw = _ida_allins.PPC_vminsw

PPC_vminub = _ida_allins.PPC_vminub

PPC_vminuh = _ida_allins.PPC_vminuh

PPC_vminuw = _ida_allins.PPC_vminuw

PPC_vmladduhm = _ida_allins.PPC_vmladduhm

PPC_vmrghb = _ida_allins.PPC_vmrghb

PPC_vmrghh = _ida_allins.PPC_vmrghh

PPC_vmrghw = _ida_allins.PPC_vmrghw

PPC_vmrglb = _ida_allins.PPC_vmrglb

PPC_vmrglh = _ida_allins.PPC_vmrglh

PPC_vmrglw = _ida_allins.PPC_vmrglw

PPC_vmsummbm = _ida_allins.PPC_vmsummbm

PPC_vmsumshm = _ida_allins.PPC_vmsumshm

PPC_vmsumshs = _ida_allins.PPC_vmsumshs

PPC_vmsumubm = _ida_allins.PPC_vmsumubm

PPC_vmsumuhm = _ida_allins.PPC_vmsumuhm

PPC_vmsumuhs = _ida_allins.PPC_vmsumuhs

PPC_vmulesb = _ida_allins.PPC_vmulesb

PPC_vmulesh = _ida_allins.PPC_vmulesh

PPC_vmuleub = _ida_allins.PPC_vmuleub

PPC_vmuleuh = _ida_allins.PPC_vmuleuh

PPC_vmulosb = _ida_allins.PPC_vmulosb

PPC_vmulosh = _ida_allins.PPC_vmulosh

PPC_vmuloub = _ida_allins.PPC_vmuloub

PPC_vmulouh = _ida_allins.PPC_vmulouh

PPC_vnmsubfp = _ida_allins.PPC_vnmsubfp

PPC_vnor = _ida_allins.PPC_vnor

PPC_vor = _ida_allins.PPC_vor

PPC_vperm = _ida_allins.PPC_vperm

PPC_vpkpx = _ida_allins.PPC_vpkpx

PPC_vpkshss = _ida_allins.PPC_vpkshss

PPC_vpkshus = _ida_allins.PPC_vpkshus

PPC_vpkswss = _ida_allins.PPC_vpkswss

PPC_vpkswus = _ida_allins.PPC_vpkswus

PPC_vpkuhum = _ida_allins.PPC_vpkuhum

PPC_vpkuhus = _ida_allins.PPC_vpkuhus

PPC_vpkuwum = _ida_allins.PPC_vpkuwum

PPC_vpkuwus = _ida_allins.PPC_vpkuwus

PPC_vrefp = _ida_allins.PPC_vrefp

PPC_vrfim = _ida_allins.PPC_vrfim

PPC_vrfin = _ida_allins.PPC_vrfin

PPC_vrfip = _ida_allins.PPC_vrfip

PPC_vrfiz = _ida_allins.PPC_vrfiz

PPC_vrlb = _ida_allins.PPC_vrlb

PPC_vrlh = _ida_allins.PPC_vrlh

PPC_vrlw = _ida_allins.PPC_vrlw

PPC_vrsqrtefp = _ida_allins.PPC_vrsqrtefp

PPC_vsel = _ida_allins.PPC_vsel

PPC_vsl = _ida_allins.PPC_vsl

PPC_vslb = _ida_allins.PPC_vslb

PPC_vsldoi = _ida_allins.PPC_vsldoi

PPC_vslh = _ida_allins.PPC_vslh

PPC_vslo = _ida_allins.PPC_vslo

PPC_vslw = _ida_allins.PPC_vslw

PPC_vspltb = _ida_allins.PPC_vspltb

PPC_vsplth = _ida_allins.PPC_vsplth

PPC_vspltisb = _ida_allins.PPC_vspltisb

PPC_vspltish = _ida_allins.PPC_vspltish

PPC_vspltisw = _ida_allins.PPC_vspltisw

PPC_vspltw = _ida_allins.PPC_vspltw

PPC_vsr = _ida_allins.PPC_vsr

PPC_vsrab = _ida_allins.PPC_vsrab

PPC_vsrah = _ida_allins.PPC_vsrah

PPC_vsraw = _ida_allins.PPC_vsraw

PPC_vsrb = _ida_allins.PPC_vsrb

PPC_vsrh = _ida_allins.PPC_vsrh

PPC_vsro = _ida_allins.PPC_vsro

PPC_vsrw = _ida_allins.PPC_vsrw

PPC_vsubcuw = _ida_allins.PPC_vsubcuw

PPC_vsubfp = _ida_allins.PPC_vsubfp

PPC_vsubsbs = _ida_allins.PPC_vsubsbs

PPC_vsubshs = _ida_allins.PPC_vsubshs

PPC_vsubsws = _ida_allins.PPC_vsubsws

PPC_vsububm = _ida_allins.PPC_vsububm

PPC_vsububs = _ida_allins.PPC_vsububs

PPC_vsubuhm = _ida_allins.PPC_vsubuhm

PPC_vsubuhs = _ida_allins.PPC_vsubuhs

PPC_vsubuwm = _ida_allins.PPC_vsubuwm

PPC_vsubuws = _ida_allins.PPC_vsubuws

PPC_vsum2sws = _ida_allins.PPC_vsum2sws

PPC_vsum4sbs = _ida_allins.PPC_vsum4sbs

PPC_vsum4shs = _ida_allins.PPC_vsum4shs

PPC_vsum4ubs = _ida_allins.PPC_vsum4ubs

PPC_vsumsws = _ida_allins.PPC_vsumsws

PPC_vupkhpx = _ida_allins.PPC_vupkhpx

PPC_vupkhsb = _ida_allins.PPC_vupkhsb

PPC_vupkhsh = _ida_allins.PPC_vupkhsh

PPC_vupklpx = _ida_allins.PPC_vupklpx

PPC_vupklsb = _ida_allins.PPC_vupklsb

PPC_vupklsh = _ida_allins.PPC_vupklsh

PPC_vxor = _ida_allins.PPC_vxor

PPC_lxsdx = _ida_allins.PPC_lxsdx

PPC_lxvd2x = _ida_allins.PPC_lxvd2x

PPC_lxvdsx = _ida_allins.PPC_lxvdsx

PPC_lxvw4x = _ida_allins.PPC_lxvw4x

PPC_stxsdx = _ida_allins.PPC_stxsdx

PPC_stxvd2x = _ida_allins.PPC_stxvd2x

PPC_stxvw4x = _ida_allins.PPC_stxvw4x

PPC_xsabsdp = _ida_allins.PPC_xsabsdp

PPC_xsadddp = _ida_allins.PPC_xsadddp

PPC_xscmpodp = _ida_allins.PPC_xscmpodp

PPC_xscmpudp = _ida_allins.PPC_xscmpudp

PPC_xscpsgndp = _ida_allins.PPC_xscpsgndp

PPC_xscvdpsp = _ida_allins.PPC_xscvdpsp

PPC_xscvdpsxds = _ida_allins.PPC_xscvdpsxds

PPC_xscvdpsxws = _ida_allins.PPC_xscvdpsxws

PPC_xscvdpuxds = _ida_allins.PPC_xscvdpuxds

PPC_xscvdpuxws = _ida_allins.PPC_xscvdpuxws

PPC_xscvspdp = _ida_allins.PPC_xscvspdp

PPC_xscvsxddp = _ida_allins.PPC_xscvsxddp

PPC_xscvuxddp = _ida_allins.PPC_xscvuxddp

PPC_xsdivdp = _ida_allins.PPC_xsdivdp

PPC_xsmaddadp = _ida_allins.PPC_xsmaddadp

PPC_xsmaddmdp = _ida_allins.PPC_xsmaddmdp

PPC_xsmaxdp = _ida_allins.PPC_xsmaxdp

PPC_xsmindp = _ida_allins.PPC_xsmindp

PPC_xsmsubadp = _ida_allins.PPC_xsmsubadp

PPC_xsmsubmdp = _ida_allins.PPC_xsmsubmdp

PPC_xsmuldp = _ida_allins.PPC_xsmuldp

PPC_xsnabsdp = _ida_allins.PPC_xsnabsdp

PPC_xsnegdp = _ida_allins.PPC_xsnegdp

PPC_xsnmaddadp = _ida_allins.PPC_xsnmaddadp

PPC_xsnmaddmdp = _ida_allins.PPC_xsnmaddmdp

PPC_xsnmsubadp = _ida_allins.PPC_xsnmsubadp

PPC_xsnmsubmdp = _ida_allins.PPC_xsnmsubmdp

PPC_xsrdpi = _ida_allins.PPC_xsrdpi

PPC_xsrdpic = _ida_allins.PPC_xsrdpic

PPC_xsrdpim = _ida_allins.PPC_xsrdpim

PPC_xsrdpip = _ida_allins.PPC_xsrdpip

PPC_xsrdpiz = _ida_allins.PPC_xsrdpiz

PPC_xsredp = _ida_allins.PPC_xsredp

PPC_xsrsqrtedp = _ida_allins.PPC_xsrsqrtedp

PPC_xssqrtdp = _ida_allins.PPC_xssqrtdp

PPC_xssubdp = _ida_allins.PPC_xssubdp

PPC_xstdivdp = _ida_allins.PPC_xstdivdp

PPC_xstsqrtdp = _ida_allins.PPC_xstsqrtdp

PPC_xvabsdp = _ida_allins.PPC_xvabsdp

PPC_xvabssp = _ida_allins.PPC_xvabssp

PPC_xvadddp = _ida_allins.PPC_xvadddp

PPC_xvaddsp = _ida_allins.PPC_xvaddsp

PPC_xvcmpeqdp = _ida_allins.PPC_xvcmpeqdp

PPC_xvcmpeqsp = _ida_allins.PPC_xvcmpeqsp

PPC_xvcmpgedp = _ida_allins.PPC_xvcmpgedp

PPC_xvcmpgesp = _ida_allins.PPC_xvcmpgesp

PPC_xvcmpgtdp = _ida_allins.PPC_xvcmpgtdp

PPC_xvcmpgtsp = _ida_allins.PPC_xvcmpgtsp

PPC_xvcpsgndp = _ida_allins.PPC_xvcpsgndp

PPC_xvcpsgnsp = _ida_allins.PPC_xvcpsgnsp

PPC_xvcvdpsp = _ida_allins.PPC_xvcvdpsp

PPC_xvcvdpsxds = _ida_allins.PPC_xvcvdpsxds

PPC_xvcvdpsxws = _ida_allins.PPC_xvcvdpsxws

PPC_xvcvdpuxds = _ida_allins.PPC_xvcvdpuxds

PPC_xvcvdpuxws = _ida_allins.PPC_xvcvdpuxws

PPC_xvcvspdp = _ida_allins.PPC_xvcvspdp

PPC_xvcvspsxds = _ida_allins.PPC_xvcvspsxds

PPC_xvcvspsxws = _ida_allins.PPC_xvcvspsxws

PPC_xvcvspuxds = _ida_allins.PPC_xvcvspuxds

PPC_xvcvspuxws = _ida_allins.PPC_xvcvspuxws

PPC_xvcvsxddp = _ida_allins.PPC_xvcvsxddp

PPC_xvcvsxdsp = _ida_allins.PPC_xvcvsxdsp

PPC_xvcvsxwdp = _ida_allins.PPC_xvcvsxwdp

PPC_xvcvsxwsp = _ida_allins.PPC_xvcvsxwsp

PPC_xvcvuxddp = _ida_allins.PPC_xvcvuxddp

PPC_xvcvuxdsp = _ida_allins.PPC_xvcvuxdsp

PPC_xvcvuxwdp = _ida_allins.PPC_xvcvuxwdp

PPC_xvcvuxwsp = _ida_allins.PPC_xvcvuxwsp

PPC_xvdivdp = _ida_allins.PPC_xvdivdp

PPC_xvdivsp = _ida_allins.PPC_xvdivsp

PPC_xvmaddadp = _ida_allins.PPC_xvmaddadp

PPC_xvmaddasp = _ida_allins.PPC_xvmaddasp

PPC_xvmaddmdp = _ida_allins.PPC_xvmaddmdp

PPC_xvmaddmsp = _ida_allins.PPC_xvmaddmsp

PPC_xvmaxdp = _ida_allins.PPC_xvmaxdp

PPC_xvmaxsp = _ida_allins.PPC_xvmaxsp

PPC_xvmindp = _ida_allins.PPC_xvmindp

PPC_xvminsp = _ida_allins.PPC_xvminsp

PPC_xvmsubadp = _ida_allins.PPC_xvmsubadp

PPC_xvmsubasp = _ida_allins.PPC_xvmsubasp

PPC_xvmsubmdp = _ida_allins.PPC_xvmsubmdp

PPC_xvmsubmsp = _ida_allins.PPC_xvmsubmsp

PPC_xvmuldp = _ida_allins.PPC_xvmuldp

PPC_xvmulsp = _ida_allins.PPC_xvmulsp

PPC_xvnabsdp = _ida_allins.PPC_xvnabsdp

PPC_xvnabssp = _ida_allins.PPC_xvnabssp

PPC_xvnegdp = _ida_allins.PPC_xvnegdp

PPC_xvnegsp = _ida_allins.PPC_xvnegsp

PPC_xvnmaddadp = _ida_allins.PPC_xvnmaddadp

PPC_xvnmaddasp = _ida_allins.PPC_xvnmaddasp

PPC_xvnmaddmdp = _ida_allins.PPC_xvnmaddmdp

PPC_xvnmaddmsp = _ida_allins.PPC_xvnmaddmsp

PPC_xvnmsubadp = _ida_allins.PPC_xvnmsubadp

PPC_xvnmsubasp = _ida_allins.PPC_xvnmsubasp

PPC_xvnmsubmdp = _ida_allins.PPC_xvnmsubmdp

PPC_xvnmsubmsp = _ida_allins.PPC_xvnmsubmsp

PPC_xvrdpi = _ida_allins.PPC_xvrdpi

PPC_xvrdpic = _ida_allins.PPC_xvrdpic

PPC_xvrdpim = _ida_allins.PPC_xvrdpim

PPC_xvrdpip = _ida_allins.PPC_xvrdpip

PPC_xvrdpiz = _ida_allins.PPC_xvrdpiz

PPC_xvredp = _ida_allins.PPC_xvredp

PPC_xvresp = _ida_allins.PPC_xvresp

PPC_xvrspi = _ida_allins.PPC_xvrspi

PPC_xvrspic = _ida_allins.PPC_xvrspic

PPC_xvrspim = _ida_allins.PPC_xvrspim

PPC_xvrspip = _ida_allins.PPC_xvrspip

PPC_xvrspiz = _ida_allins.PPC_xvrspiz

PPC_xvrsqrtedp = _ida_allins.PPC_xvrsqrtedp

PPC_xvrsqrtesp = _ida_allins.PPC_xvrsqrtesp

PPC_xvsqrtdp = _ida_allins.PPC_xvsqrtdp

PPC_xvsqrtsp = _ida_allins.PPC_xvsqrtsp

PPC_xvsubdp = _ida_allins.PPC_xvsubdp

PPC_xvsubsp = _ida_allins.PPC_xvsubsp

PPC_xvtdivdp = _ida_allins.PPC_xvtdivdp

PPC_xvtdivsp = _ida_allins.PPC_xvtdivsp

PPC_xvtsqrtdp = _ida_allins.PPC_xvtsqrtdp

PPC_xvtsqrtsp = _ida_allins.PPC_xvtsqrtsp

PPC_xxland = _ida_allins.PPC_xxland

PPC_xxlandc = _ida_allins.PPC_xxlandc

PPC_xxlnor = _ida_allins.PPC_xxlnor

PPC_xxlor = _ida_allins.PPC_xxlor

PPC_xxlxor = _ida_allins.PPC_xxlxor

PPC_xxmrghw = _ida_allins.PPC_xxmrghw

PPC_xxmrglw = _ida_allins.PPC_xxmrglw

PPC_xxpermdi = _ida_allins.PPC_xxpermdi

PPC_xxsel = _ida_allins.PPC_xxsel

PPC_xxsldwi = _ida_allins.PPC_xxsldwi

PPC_xxspltw = _ida_allins.PPC_xxspltw

PPC_wait = _ida_allins.PPC_wait

PPC_dss = _ida_allins.PPC_dss

PPC_dssall = _ida_allins.PPC_dssall

PPC_dst = _ida_allins.PPC_dst

PPC_dstt = _ida_allins.PPC_dstt

PPC_dstst = _ida_allins.PPC_dstst

PPC_dststt = _ida_allins.PPC_dststt

PPC_lvlx = _ida_allins.PPC_lvlx

PPC_lvlxl = _ida_allins.PPC_lvlxl

PPC_lvrx = _ida_allins.PPC_lvrx

PPC_lvrxl = _ida_allins.PPC_lvrxl

PPC_stvlx = _ida_allins.PPC_stvlx

PPC_stvlxl = _ida_allins.PPC_stvlxl

PPC_stvrx = _ida_allins.PPC_stvrx

PPC_stvrxl = _ida_allins.PPC_stvrxl

PPC_add16i = _ida_allins.PPC_add16i

PPC_add2i = _ida_allins.PPC_add2i

PPC_add2is = _ida_allins.PPC_add2is

PPC_and2i = _ida_allins.PPC_and2i

PPC_and2is = _ida_allins.PPC_and2is

PPC_cmp16i = _ida_allins.PPC_cmp16i

PPC_cmph = _ida_allins.PPC_cmph

PPC_cmph16i = _ida_allins.PPC_cmph16i

PPC_cmphl = _ida_allins.PPC_cmphl

PPC_cmphl16i = _ida_allins.PPC_cmphl16i

PPC_cmpl16i = _ida_allins.PPC_cmpl16i

PPC_mull2i = _ida_allins.PPC_mull2i

PPC_or2i = _ida_allins.PPC_or2i

PPC_or2is = _ida_allins.PPC_or2is

PPC_rlw = _ida_allins.PPC_rlw

PPC_rlwi = _ida_allins.PPC_rlwi

PPC_bclri = _ida_allins.PPC_bclri

PPC_bgeni = _ida_allins.PPC_bgeni

PPC_bmaski = _ida_allins.PPC_bmaski

PPC_bseti = _ida_allins.PPC_bseti

PPC_btsti = _ida_allins.PPC_btsti

PPC_extzb = _ida_allins.PPC_extzb

PPC_extzh = _ida_allins.PPC_extzh

PPC_illegal = _ida_allins.PPC_illegal

PPC_mfar = _ida_allins.PPC_mfar

PPC_mtar = _ida_allins.PPC_mtar

PPC_sub = _ida_allins.PPC_sub

PPC_sub16i = _ida_allins.PPC_sub16i

PPC_sub2i = _ida_allins.PPC_sub2i

PPC_sub2is = _ida_allins.PPC_sub2is

PPC_extldi = _ida_allins.PPC_extldi

PPC_extrdi = _ida_allins.PPC_extrdi

PPC_insrdi = _ida_allins.PPC_insrdi

PPC_rotldi = _ida_allins.PPC_rotldi

PPC_rotrdi = _ida_allins.PPC_rotrdi

PPC_rotld = _ida_allins.PPC_rotld

PPC_sldi = _ida_allins.PPC_sldi

PPC_srdi = _ida_allins.PPC_srdi

PPC_clrldi = _ida_allins.PPC_clrldi

PPC_clrrdi = _ida_allins.PPC_clrrdi

PPC_clrlsldi = _ida_allins.PPC_clrlsldi

PPC_xnop = _ida_allins.PPC_xnop

PPC_hnop = _ida_allins.PPC_hnop

PPC_dcbfl = _ida_allins.PPC_dcbfl

PPC_dcbflp = _ida_allins.PPC_dcbflp

PPC_dcbtt = _ida_allins.PPC_dcbtt

PPC_dcbtstt = _ida_allins.PPC_dcbtstt

PPC_lwsync = _ida_allins.PPC_lwsync

PPC_ptesync = _ida_allins.PPC_ptesync

PPC_waitrsv = _ida_allins.PPC_waitrsv

PPC_waitimpl = _ida_allins.PPC_waitimpl

PPC_evmr = _ida_allins.PPC_evmr

PPC_evnot = _ida_allins.PPC_evnot

PPC_mtcr = _ida_allins.PPC_mtcr

PPC_xvmovdp = _ida_allins.PPC_xvmovdp

PPC_xvmovsp = _ida_allins.PPC_xvmovsp

PPC_xxspltd = _ida_allins.PPC_xxspltd

PPC_xxmrghd = _ida_allins.PPC_xxmrghd

PPC_xxmrgld = _ida_allins.PPC_xxmrgld

PPC_xxswapd = _ida_allins.PPC_xxswapd

PPC_dcbz128 = _ida_allins.PPC_dcbz128

PPC_mtmsree = _ida_allins.PPC_mtmsree

PPC_vcfpsxws = _ida_allins.PPC_vcfpsxws

PPC_vcfpuxws = _ida_allins.PPC_vcfpuxws

PPC_vcsxwfp = _ida_allins.PPC_vcsxwfp

PPC_vcuxwfp = _ida_allins.PPC_vcuxwfp

PPC_vmaddcfp = _ida_allins.PPC_vmaddcfp

PPC_vmsum3fp = _ida_allins.PPC_vmsum3fp

PPC_vmsum4fp = _ida_allins.PPC_vmsum4fp

PPC_vmulfp = _ida_allins.PPC_vmulfp

PPC_vpermwi = _ida_allins.PPC_vpermwi

PPC_vpkd3d = _ida_allins.PPC_vpkd3d

PPC_vrlimi = _ida_allins.PPC_vrlimi

PPC_vupkd3d = _ida_allins.PPC_vupkd3d

PPC_ps_cmpu0 = _ida_allins.PPC_ps_cmpu0

PPC_psq_lx = _ida_allins.PPC_psq_lx

PPC_psq_stx = _ida_allins.PPC_psq_stx

PPC_ps_sum0 = _ida_allins.PPC_ps_sum0

PPC_ps_sum1 = _ida_allins.PPC_ps_sum1

PPC_ps_muls0 = _ida_allins.PPC_ps_muls0

PPC_ps_muls1 = _ida_allins.PPC_ps_muls1

PPC_ps_madds0 = _ida_allins.PPC_ps_madds0

PPC_ps_madds1 = _ida_allins.PPC_ps_madds1

PPC_ps_div = _ida_allins.PPC_ps_div

PPC_ps_sub = _ida_allins.PPC_ps_sub

PPC_ps_add = _ida_allins.PPC_ps_add

PPC_ps_sel = _ida_allins.PPC_ps_sel

PPC_ps_res = _ida_allins.PPC_ps_res

PPC_ps_mul = _ida_allins.PPC_ps_mul

PPC_ps_rsqrte = _ida_allins.PPC_ps_rsqrte

PPC_ps_msub = _ida_allins.PPC_ps_msub

PPC_ps_madd = _ida_allins.PPC_ps_madd

PPC_ps_nmsub = _ida_allins.PPC_ps_nmsub

PPC_ps_nmadd = _ida_allins.PPC_ps_nmadd

PPC_ps_cmpo0 = _ida_allins.PPC_ps_cmpo0

PPC_psq_lux = _ida_allins.PPC_psq_lux

PPC_psq_stux = _ida_allins.PPC_psq_stux

PPC_ps_neg = _ida_allins.PPC_ps_neg

PPC_ps_cmpu1 = _ida_allins.PPC_ps_cmpu1

PPC_ps_mr = _ida_allins.PPC_ps_mr

PPC_ps_cmpo1 = _ida_allins.PPC_ps_cmpo1

PPC_ps_nabs = _ida_allins.PPC_ps_nabs

PPC_ps_abs = _ida_allins.PPC_ps_abs

PPC_ps_merge00 = _ida_allins.PPC_ps_merge00

PPC_ps_merge01 = _ida_allins.PPC_ps_merge01

PPC_ps_merge10 = _ida_allins.PPC_ps_merge10

PPC_ps_merge11 = _ida_allins.PPC_ps_merge11

PPC_dcbz_l = _ida_allins.PPC_dcbz_l

PPC_psq_l = _ida_allins.PPC_psq_l

PPC_psq_lu = _ida_allins.PPC_psq_lu

PPC_psq_st = _ida_allins.PPC_psq_st

PPC_psq_stu = _ida_allins.PPC_psq_stu

PPC_evfsmadd = _ida_allins.PPC_evfsmadd

PPC_evfsmsub = _ida_allins.PPC_evfsmsub

PPC_evfssqrt = _ida_allins.PPC_evfssqrt

PPC_evfsnmadd = _ida_allins.PPC_evfsnmadd

PPC_evfsnmsub = _ida_allins.PPC_evfsnmsub

PPC_evfsmax = _ida_allins.PPC_evfsmax

PPC_evfsmin = _ida_allins.PPC_evfsmin

PPC_evfsaddsub = _ida_allins.PPC_evfsaddsub

PPC_evfssubadd = _ida_allins.PPC_evfssubadd

PPC_evfssum = _ida_allins.PPC_evfssum

PPC_evfsdiff = _ida_allins.PPC_evfsdiff

PPC_evfssumdiff = _ida_allins.PPC_evfssumdiff

PPC_evfsdiffsum = _ida_allins.PPC_evfsdiffsum

PPC_evfsaddx = _ida_allins.PPC_evfsaddx

PPC_evfssubx = _ida_allins.PPC_evfssubx

PPC_evfsaddsubx = _ida_allins.PPC_evfsaddsubx

PPC_evfssubaddx = _ida_allins.PPC_evfssubaddx

PPC_evfsmulx = _ida_allins.PPC_evfsmulx

PPC_evfsmule = _ida_allins.PPC_evfsmule

PPC_evfsmulo = _ida_allins.PPC_evfsmulo

PPC_evfscfh = _ida_allins.PPC_evfscfh

PPC_evfscth = _ida_allins.PPC_evfscth

PPC_efsmax = _ida_allins.PPC_efsmax

PPC_efsmin = _ida_allins.PPC_efsmin

PPC_efsmadd = _ida_allins.PPC_efsmadd

PPC_efsmsub = _ida_allins.PPC_efsmsub

PPC_efssqrt = _ida_allins.PPC_efssqrt

PPC_efsnmadd = _ida_allins.PPC_efsnmadd

PPC_efsnmsub = _ida_allins.PPC_efsnmsub

PPC_efscfh = _ida_allins.PPC_efscfh

PPC_efscth = _ida_allins.PPC_efscth

PPC_lmvgprw = _ida_allins.PPC_lmvgprw

PPC_stmvgprw = _ida_allins.PPC_stmvgprw

PPC_lmvsprw = _ida_allins.PPC_lmvsprw

PPC_stmvsprw = _ida_allins.PPC_stmvsprw

PPC_lmvsrrw = _ida_allins.PPC_lmvsrrw

PPC_stmvsrrw = _ida_allins.PPC_stmvsrrw

PPC_lmvcsrrw = _ida_allins.PPC_lmvcsrrw

PPC_stmvcsrrw = _ida_allins.PPC_stmvcsrrw

PPC_lmvdsrrw = _ida_allins.PPC_lmvdsrrw

PPC_stmvdsrrw = _ida_allins.PPC_stmvdsrrw

PPC_lmvmcsrrw = _ida_allins.PPC_lmvmcsrrw

PPC_stmvmcsrrw = _ida_allins.PPC_stmvmcsrrw

PPC_evdotpwcssi = _ida_allins.PPC_evdotpwcssi

PPC_evdotpwcsmi = _ida_allins.PPC_evdotpwcsmi

PPC_evdotpwcssfr = _ida_allins.PPC_evdotpwcssfr

PPC_evdotpwcssf = _ida_allins.PPC_evdotpwcssf

PPC_evdotpwgasmf = _ida_allins.PPC_evdotpwgasmf

PPC_evdotpwxgasmf = _ida_allins.PPC_evdotpwxgasmf

PPC_evdotpwgasmfr = _ida_allins.PPC_evdotpwgasmfr

PPC_evdotpwxgasmfr = _ida_allins.PPC_evdotpwxgasmfr

PPC_evdotpwgssmf = _ida_allins.PPC_evdotpwgssmf

PPC_evdotpwxgssmf = _ida_allins.PPC_evdotpwxgssmf

PPC_evdotpwgssmfr = _ida_allins.PPC_evdotpwgssmfr

PPC_evdotpwxgssmfr = _ida_allins.PPC_evdotpwxgssmfr

PPC_evdotpwcssiaaw3 = _ida_allins.PPC_evdotpwcssiaaw3

PPC_evdotpwcsmiaaw3 = _ida_allins.PPC_evdotpwcsmiaaw3

PPC_evdotpwcssfraaw3 = _ida_allins.PPC_evdotpwcssfraaw3

PPC_evdotpwcssfaaw3 = _ida_allins.PPC_evdotpwcssfaaw3

PPC_evdotpwgasmfaa3 = _ida_allins.PPC_evdotpwgasmfaa3

PPC_evdotpwxgasmfaa3 = _ida_allins.PPC_evdotpwxgasmfaa3

PPC_evdotpwgasmfraa3 = _ida_allins.PPC_evdotpwgasmfraa3

PPC_evdotpwxgasmfraa3 = _ida_allins.PPC_evdotpwxgasmfraa3

PPC_evdotpwgssmfaa3 = _ida_allins.PPC_evdotpwgssmfaa3

PPC_evdotpwxgssmfaa3 = _ida_allins.PPC_evdotpwxgssmfaa3

PPC_evdotpwgssmfraa3 = _ida_allins.PPC_evdotpwgssmfraa3

PPC_evdotpwxgssmfraa3 = _ida_allins.PPC_evdotpwxgssmfraa3

PPC_evdotpwcssia = _ida_allins.PPC_evdotpwcssia

PPC_evdotpwcsmia = _ida_allins.PPC_evdotpwcsmia

PPC_evdotpwcssfra = _ida_allins.PPC_evdotpwcssfra

PPC_evdotpwcssfa = _ida_allins.PPC_evdotpwcssfa

PPC_evdotpwgasmfa = _ida_allins.PPC_evdotpwgasmfa

PPC_evdotpwxgasmfa = _ida_allins.PPC_evdotpwxgasmfa

PPC_evdotpwgasmfra = _ida_allins.PPC_evdotpwgasmfra

PPC_evdotpwxgasmfra = _ida_allins.PPC_evdotpwxgasmfra

PPC_evdotpwgssmfa = _ida_allins.PPC_evdotpwgssmfa

PPC_evdotpwxgssmfa = _ida_allins.PPC_evdotpwxgssmfa

PPC_evdotpwgssmfra = _ida_allins.PPC_evdotpwgssmfra

PPC_evdotpwxgssmfra = _ida_allins.PPC_evdotpwxgssmfra

PPC_evdotpwcssiaaw = _ida_allins.PPC_evdotpwcssiaaw

PPC_evdotpwcsmiaaw = _ida_allins.PPC_evdotpwcsmiaaw

PPC_evdotpwcssfraaw = _ida_allins.PPC_evdotpwcssfraaw

PPC_evdotpwcssfaaw = _ida_allins.PPC_evdotpwcssfaaw

PPC_evdotpwgasmfaa = _ida_allins.PPC_evdotpwgasmfaa

PPC_evdotpwxgasmfaa = _ida_allins.PPC_evdotpwxgasmfaa

PPC_evdotpwgasmfraa = _ida_allins.PPC_evdotpwgasmfraa

PPC_evdotpwxgasmfraa = _ida_allins.PPC_evdotpwxgasmfraa

PPC_evdotpwgssmfaa = _ida_allins.PPC_evdotpwgssmfaa

PPC_evdotpwxgssmfaa = _ida_allins.PPC_evdotpwxgssmfaa

PPC_evdotpwgssmfraa = _ida_allins.PPC_evdotpwgssmfraa

PPC_evdotpwxgssmfraa = _ida_allins.PPC_evdotpwxgssmfraa

PPC_evdotphihcssi = _ida_allins.PPC_evdotphihcssi

PPC_evdotplohcssi = _ida_allins.PPC_evdotplohcssi

PPC_evdotphihcssf = _ida_allins.PPC_evdotphihcssf

PPC_evdotplohcssf = _ida_allins.PPC_evdotplohcssf

PPC_evdotphihcsmi = _ida_allins.PPC_evdotphihcsmi

PPC_evdotplohcsmi = _ida_allins.PPC_evdotplohcsmi

PPC_evdotphihcssfr = _ida_allins.PPC_evdotphihcssfr

PPC_evdotplohcssfr = _ida_allins.PPC_evdotplohcssfr

PPC_evdotphihcssiaaw3 = _ida_allins.PPC_evdotphihcssiaaw3

PPC_evdotplohcssiaaw3 = _ida_allins.PPC_evdotplohcssiaaw3

PPC_evdotphihcssfaaw3 = _ida_allins.PPC_evdotphihcssfaaw3

PPC_evdotplohcssfaaw3 = _ida_allins.PPC_evdotplohcssfaaw3

PPC_evdotphihcsmiaaw3 = _ida_allins.PPC_evdotphihcsmiaaw3

PPC_evdotplohcsmiaaw3 = _ida_allins.PPC_evdotplohcsmiaaw3

PPC_evdotphihcssfraaw3 = _ida_allins.PPC_evdotphihcssfraaw3

PPC_evdotplohcssfraaw3 = _ida_allins.PPC_evdotplohcssfraaw3

PPC_evdotphihcssia = _ida_allins.PPC_evdotphihcssia

PPC_evdotplohcssia = _ida_allins.PPC_evdotplohcssia

PPC_evdotphihcssfa = _ida_allins.PPC_evdotphihcssfa

PPC_evdotplohcssfa = _ida_allins.PPC_evdotplohcssfa

PPC_evdotphihcsmia = _ida_allins.PPC_evdotphihcsmia

PPC_evdotplohcsmia = _ida_allins.PPC_evdotplohcsmia

PPC_evdotphihcssfra = _ida_allins.PPC_evdotphihcssfra

PPC_evdotplohcssfra = _ida_allins.PPC_evdotplohcssfra

PPC_evdotphihcssiaaw = _ida_allins.PPC_evdotphihcssiaaw

PPC_evdotplohcssiaaw = _ida_allins.PPC_evdotplohcssiaaw

PPC_evdotphihcssfaaw = _ida_allins.PPC_evdotphihcssfaaw

PPC_evdotplohcssfaaw = _ida_allins.PPC_evdotplohcssfaaw

PPC_evdotphihcsmiaaw = _ida_allins.PPC_evdotphihcsmiaaw

PPC_evdotplohcsmiaaw = _ida_allins.PPC_evdotplohcsmiaaw

PPC_evdotphihcssfraaw = _ida_allins.PPC_evdotphihcssfraaw

PPC_evdotplohcssfraaw = _ida_allins.PPC_evdotplohcssfraaw

PPC_evdotphausi = _ida_allins.PPC_evdotphausi

PPC_evdotphassi = _ida_allins.PPC_evdotphassi

PPC_evdotphasusi = _ida_allins.PPC_evdotphasusi

PPC_evdotphassf = _ida_allins.PPC_evdotphassf

PPC_evdotphsssf = _ida_allins.PPC_evdotphsssf

PPC_evdotphaumi = _ida_allins.PPC_evdotphaumi

PPC_evdotphasmi = _ida_allins.PPC_evdotphasmi

PPC_evdotphasumi = _ida_allins.PPC_evdotphasumi

PPC_evdotphassfr = _ida_allins.PPC_evdotphassfr

PPC_evdotphssmi = _ida_allins.PPC_evdotphssmi

PPC_evdotphsssfr = _ida_allins.PPC_evdotphsssfr

PPC_evdotphausiaaw3 = _ida_allins.PPC_evdotphausiaaw3

PPC_evdotphassiaaw3 = _ida_allins.PPC_evdotphassiaaw3

PPC_evdotphasusiaaw3 = _ida_allins.PPC_evdotphasusiaaw3

PPC_evdotphassfaaw3 = _ida_allins.PPC_evdotphassfaaw3

PPC_evdotphsssiaaw3 = _ida_allins.PPC_evdotphsssiaaw3

PPC_evdotphsssfaaw3 = _ida_allins.PPC_evdotphsssfaaw3

PPC_evdotphaumiaaw3 = _ida_allins.PPC_evdotphaumiaaw3

PPC_evdotphasmiaaw3 = _ida_allins.PPC_evdotphasmiaaw3

PPC_evdotphasumiaaw3 = _ida_allins.PPC_evdotphasumiaaw3

PPC_evdotphassfraaw3 = _ida_allins.PPC_evdotphassfraaw3

PPC_evdotphssmiaaw3 = _ida_allins.PPC_evdotphssmiaaw3

PPC_evdotphsssfraaw3 = _ida_allins.PPC_evdotphsssfraaw3

PPC_evdotphausia = _ida_allins.PPC_evdotphausia

PPC_evdotphassia = _ida_allins.PPC_evdotphassia

PPC_evdotphasusia = _ida_allins.PPC_evdotphasusia

PPC_evdotphassfa = _ida_allins.PPC_evdotphassfa

PPC_evdotphsssfa = _ida_allins.PPC_evdotphsssfa

PPC_evdotphaumia = _ida_allins.PPC_evdotphaumia

PPC_evdotphasmia = _ida_allins.PPC_evdotphasmia

PPC_evdotphasumia = _ida_allins.PPC_evdotphasumia

PPC_evdotphassfra = _ida_allins.PPC_evdotphassfra

PPC_evdotphssmia = _ida_allins.PPC_evdotphssmia

PPC_evdotphsssfra = _ida_allins.PPC_evdotphsssfra

PPC_evdotphausiaaw = _ida_allins.PPC_evdotphausiaaw

PPC_evdotphassiaaw = _ida_allins.PPC_evdotphassiaaw

PPC_evdotphasusiaaw = _ida_allins.PPC_evdotphasusiaaw

PPC_evdotphassfaaw = _ida_allins.PPC_evdotphassfaaw

PPC_evdotphsssiaaw = _ida_allins.PPC_evdotphsssiaaw

PPC_evdotphsssfaaw = _ida_allins.PPC_evdotphsssfaaw

PPC_evdotphaumiaaw = _ida_allins.PPC_evdotphaumiaaw

PPC_evdotphasmiaaw = _ida_allins.PPC_evdotphasmiaaw

PPC_evdotphasumiaaw = _ida_allins.PPC_evdotphasumiaaw

PPC_evdotphassfraaw = _ida_allins.PPC_evdotphassfraaw

PPC_evdotphssmiaaw = _ida_allins.PPC_evdotphssmiaaw

PPC_evdotphsssfraaw = _ida_allins.PPC_evdotphsssfraaw

PPC_evdotp4hgaumi = _ida_allins.PPC_evdotp4hgaumi

PPC_evdotp4hgasmi = _ida_allins.PPC_evdotp4hgasmi

PPC_evdotp4hgasumi = _ida_allins.PPC_evdotp4hgasumi

PPC_evdotp4hgasmf = _ida_allins.PPC_evdotp4hgasmf

PPC_evdotp4hgssmi = _ida_allins.PPC_evdotp4hgssmi

PPC_evdotp4hgssmf = _ida_allins.PPC_evdotp4hgssmf

PPC_evdotp4hxgasmi = _ida_allins.PPC_evdotp4hxgasmi

PPC_evdotp4hxgasmf = _ida_allins.PPC_evdotp4hxgasmf

PPC_evdotpbaumi = _ida_allins.PPC_evdotpbaumi

PPC_evdotpbasmi = _ida_allins.PPC_evdotpbasmi

PPC_evdotpbasumi = _ida_allins.PPC_evdotpbasumi

PPC_evdotp4hxgssmi = _ida_allins.PPC_evdotp4hxgssmi

PPC_evdotp4hxgssmf = _ida_allins.PPC_evdotp4hxgssmf

PPC_evdotp4hgaumiaa3 = _ida_allins.PPC_evdotp4hgaumiaa3

PPC_evdotp4hgasmiaa3 = _ida_allins.PPC_evdotp4hgasmiaa3

PPC_evdotp4hgasumiaa3 = _ida_allins.PPC_evdotp4hgasumiaa3

PPC_evdotp4hgasmfaa3 = _ida_allins.PPC_evdotp4hgasmfaa3

PPC_evdotp4hgssmiaa3 = _ida_allins.PPC_evdotp4hgssmiaa3

PPC_evdotp4hgssmfaa3 = _ida_allins.PPC_evdotp4hgssmfaa3

PPC_evdotp4hxgasmiaa3 = _ida_allins.PPC_evdotp4hxgasmiaa3

PPC_evdotp4hxgasmfaa3 = _ida_allins.PPC_evdotp4hxgasmfaa3

PPC_evdotpbaumiaaw3 = _ida_allins.PPC_evdotpbaumiaaw3

PPC_evdotpbasmiaaw3 = _ida_allins.PPC_evdotpbasmiaaw3

PPC_evdotpbasumiaaw3 = _ida_allins.PPC_evdotpbasumiaaw3

PPC_evdotp4hxgssmiaa3 = _ida_allins.PPC_evdotp4hxgssmiaa3

PPC_evdotp4hxgssmfaa3 = _ida_allins.PPC_evdotp4hxgssmfaa3

PPC_evdotp4hgaumia = _ida_allins.PPC_evdotp4hgaumia

PPC_evdotp4hgasmia = _ida_allins.PPC_evdotp4hgasmia

PPC_evdotp4hgasumia = _ida_allins.PPC_evdotp4hgasumia

PPC_evdotp4hgasmfa = _ida_allins.PPC_evdotp4hgasmfa

PPC_evdotp4hgssmia = _ida_allins.PPC_evdotp4hgssmia

PPC_evdotp4hgssmfa = _ida_allins.PPC_evdotp4hgssmfa

PPC_evdotp4hxgasmia = _ida_allins.PPC_evdotp4hxgasmia

PPC_evdotp4hxgasmfa = _ida_allins.PPC_evdotp4hxgasmfa

PPC_evdotpbaumia = _ida_allins.PPC_evdotpbaumia

PPC_evdotpbasmia = _ida_allins.PPC_evdotpbasmia

PPC_evdotpbasumia = _ida_allins.PPC_evdotpbasumia

PPC_evdotp4hxgssmia = _ida_allins.PPC_evdotp4hxgssmia

PPC_evdotp4hxgssmfa = _ida_allins.PPC_evdotp4hxgssmfa

PPC_evdotp4hgaumiaa = _ida_allins.PPC_evdotp4hgaumiaa

PPC_evdotp4hgasmiaa = _ida_allins.PPC_evdotp4hgasmiaa

PPC_evdotp4hgasumiaa = _ida_allins.PPC_evdotp4hgasumiaa

PPC_evdotp4hgasmfaa = _ida_allins.PPC_evdotp4hgasmfaa

PPC_evdotp4hgssmiaa = _ida_allins.PPC_evdotp4hgssmiaa

PPC_evdotp4hgssmfaa = _ida_allins.PPC_evdotp4hgssmfaa

PPC_evdotp4hxgasmiaa = _ida_allins.PPC_evdotp4hxgasmiaa

PPC_evdotp4hxgasmfaa = _ida_allins.PPC_evdotp4hxgasmfaa

PPC_evdotpbaumiaaw = _ida_allins.PPC_evdotpbaumiaaw

PPC_evdotpbasmiaaw = _ida_allins.PPC_evdotpbasmiaaw

PPC_evdotpbasumiaaw = _ida_allins.PPC_evdotpbasumiaaw

PPC_evdotp4hxgssmiaa = _ida_allins.PPC_evdotp4hxgssmiaa

PPC_evdotp4hxgssmfaa = _ida_allins.PPC_evdotp4hxgssmfaa

PPC_evdotpwausi = _ida_allins.PPC_evdotpwausi

PPC_evdotpwassi = _ida_allins.PPC_evdotpwassi

PPC_evdotpwasusi = _ida_allins.PPC_evdotpwasusi

PPC_evdotpwaumi = _ida_allins.PPC_evdotpwaumi

PPC_evdotpwasmi = _ida_allins.PPC_evdotpwasmi

PPC_evdotpwasumi = _ida_allins.PPC_evdotpwasumi

PPC_evdotpwssmi = _ida_allins.PPC_evdotpwssmi

PPC_evdotpwausiaa3 = _ida_allins.PPC_evdotpwausiaa3

PPC_evdotpwassiaa3 = _ida_allins.PPC_evdotpwassiaa3

PPC_evdotpwasusiaa3 = _ida_allins.PPC_evdotpwasusiaa3

PPC_evdotpwsssiaa3 = _ida_allins.PPC_evdotpwsssiaa3

PPC_evdotpwaumiaa3 = _ida_allins.PPC_evdotpwaumiaa3

PPC_evdotpwasmiaa3 = _ida_allins.PPC_evdotpwasmiaa3

PPC_evdotpwasumiaa3 = _ida_allins.PPC_evdotpwasumiaa3

PPC_evdotpwssmiaa3 = _ida_allins.PPC_evdotpwssmiaa3

PPC_evdotpwausia = _ida_allins.PPC_evdotpwausia

PPC_evdotpwassia = _ida_allins.PPC_evdotpwassia

PPC_evdotpwasusia = _ida_allins.PPC_evdotpwasusia

PPC_evdotpwaumia = _ida_allins.PPC_evdotpwaumia

PPC_evdotpwasmia = _ida_allins.PPC_evdotpwasmia

PPC_evdotpwasumia = _ida_allins.PPC_evdotpwasumia

PPC_evdotpwssmia = _ida_allins.PPC_evdotpwssmia

PPC_evdotpwausiaa = _ida_allins.PPC_evdotpwausiaa

PPC_evdotpwassiaa = _ida_allins.PPC_evdotpwassiaa

PPC_evdotpwasusiaa = _ida_allins.PPC_evdotpwasusiaa

PPC_evdotpwsssiaa = _ida_allins.PPC_evdotpwsssiaa

PPC_evdotpwaumiaa = _ida_allins.PPC_evdotpwaumiaa

PPC_evdotpwasmiaa = _ida_allins.PPC_evdotpwasmiaa

PPC_evdotpwasumiaa = _ida_allins.PPC_evdotpwasumiaa

PPC_evdotpwssmiaa = _ida_allins.PPC_evdotpwssmiaa

PPC_evaddih = _ida_allins.PPC_evaddih

PPC_evaddib = _ida_allins.PPC_evaddib

PPC_evsubifh = _ida_allins.PPC_evsubifh

PPC_evsubifb = _ida_allins.PPC_evsubifb

PPC_evabsb = _ida_allins.PPC_evabsb

PPC_evabsh = _ida_allins.PPC_evabsh

PPC_evabsd = _ida_allins.PPC_evabsd

PPC_evabss = _ida_allins.PPC_evabss

PPC_evabsbs = _ida_allins.PPC_evabsbs

PPC_evabshs = _ida_allins.PPC_evabshs

PPC_evabsds = _ida_allins.PPC_evabsds

PPC_evnegwo = _ida_allins.PPC_evnegwo

PPC_evnegb = _ida_allins.PPC_evnegb

PPC_evnegbo = _ida_allins.PPC_evnegbo

PPC_evnegh = _ida_allins.PPC_evnegh

PPC_evnegho = _ida_allins.PPC_evnegho

PPC_evnegd = _ida_allins.PPC_evnegd

PPC_evnegs = _ida_allins.PPC_evnegs

PPC_evnegwos = _ida_allins.PPC_evnegwos

PPC_evnegbs = _ida_allins.PPC_evnegbs

PPC_evnegbos = _ida_allins.PPC_evnegbos

PPC_evneghs = _ida_allins.PPC_evneghs

PPC_evneghos = _ida_allins.PPC_evneghos

PPC_evnegds = _ida_allins.PPC_evnegds

PPC_evextzb = _ida_allins.PPC_evextzb

PPC_evextsbh = _ida_allins.PPC_evextsbh

PPC_evextsw = _ida_allins.PPC_evextsw

PPC_evrndhb = _ida_allins.PPC_evrndhb

PPC_evrnddw = _ida_allins.PPC_evrnddw

PPC_evrndwhus = _ida_allins.PPC_evrndwhus

PPC_evrndwhss = _ida_allins.PPC_evrndwhss

PPC_evrndhbus = _ida_allins.PPC_evrndhbus

PPC_evrndhbss = _ida_allins.PPC_evrndhbss

PPC_evrnddwus = _ida_allins.PPC_evrnddwus

PPC_evrnddwss = _ida_allins.PPC_evrnddwss

PPC_evrndwnh = _ida_allins.PPC_evrndwnh

PPC_evrndhnb = _ida_allins.PPC_evrndhnb

PPC_evrnddnw = _ida_allins.PPC_evrnddnw

PPC_evrndwnhus = _ida_allins.PPC_evrndwnhus

PPC_evrndwnhss = _ida_allins.PPC_evrndwnhss

PPC_evrndhnbus = _ida_allins.PPC_evrndhnbus

PPC_evrndhnbss = _ida_allins.PPC_evrndhnbss

PPC_evrnddnwus = _ida_allins.PPC_evrnddnwus

PPC_evrnddnwss = _ida_allins.PPC_evrnddnwss

PPC_evcntlzh = _ida_allins.PPC_evcntlzh

PPC_evcntlsh = _ida_allins.PPC_evcntlsh

PPC_evpopcntb = _ida_allins.PPC_evpopcntb

PPC_circinc = _ida_allins.PPC_circinc

PPC_evunpkhibui = _ida_allins.PPC_evunpkhibui

PPC_evunpkhibsi = _ida_allins.PPC_evunpkhibsi

PPC_evunpkhihui = _ida_allins.PPC_evunpkhihui

PPC_evunpkhihsi = _ida_allins.PPC_evunpkhihsi

PPC_evunpklobui = _ida_allins.PPC_evunpklobui

PPC_evunpklobsi = _ida_allins.PPC_evunpklobsi

PPC_evunpklohui = _ida_allins.PPC_evunpklohui

PPC_evunpklohsi = _ida_allins.PPC_evunpklohsi

PPC_evunpklohf = _ida_allins.PPC_evunpklohf

PPC_evunpkhihf = _ida_allins.PPC_evunpkhihf

PPC_evunpklowgsf = _ida_allins.PPC_evunpklowgsf

PPC_evunpkhiwgsf = _ida_allins.PPC_evunpkhiwgsf

PPC_evsatsduw = _ida_allins.PPC_evsatsduw

PPC_evsatsdsw = _ida_allins.PPC_evsatsdsw

PPC_evsatshub = _ida_allins.PPC_evsatshub

PPC_evsatshsb = _ida_allins.PPC_evsatshsb

PPC_evsatuwuh = _ida_allins.PPC_evsatuwuh

PPC_evsatswsh = _ida_allins.PPC_evsatswsh

PPC_evsatswuh = _ida_allins.PPC_evsatswuh

PPC_evsatuhub = _ida_allins.PPC_evsatuhub

PPC_evsatuduw = _ida_allins.PPC_evsatuduw

PPC_evsatuwsw = _ida_allins.PPC_evsatuwsw

PPC_evsatshuh = _ida_allins.PPC_evsatshuh

PPC_evsatuhsh = _ida_allins.PPC_evsatuhsh

PPC_evsatswuw = _ida_allins.PPC_evsatswuw

PPC_evsatswgsdf = _ida_allins.PPC_evsatswgsdf

PPC_evsatsbub = _ida_allins.PPC_evsatsbub

PPC_evsatubsb = _ida_allins.PPC_evsatubsb

PPC_evmaxhpuw = _ida_allins.PPC_evmaxhpuw

PPC_evmaxhpsw = _ida_allins.PPC_evmaxhpsw

PPC_evmaxbpuh = _ida_allins.PPC_evmaxbpuh

PPC_evmaxbpsh = _ida_allins.PPC_evmaxbpsh

PPC_evmaxwpud = _ida_allins.PPC_evmaxwpud

PPC_evmaxwpsd = _ida_allins.PPC_evmaxwpsd

PPC_evminhpuw = _ida_allins.PPC_evminhpuw

PPC_evminhpsw = _ida_allins.PPC_evminhpsw

PPC_evminbpuh = _ida_allins.PPC_evminbpuh

PPC_evminbpsh = _ida_allins.PPC_evminbpsh

PPC_evminwpud = _ida_allins.PPC_evminwpud

PPC_evminwpsd = _ida_allins.PPC_evminwpsd

PPC_evmaxmagws = _ida_allins.PPC_evmaxmagws

PPC_evsl = _ida_allins.PPC_evsl

PPC_evsli = _ida_allins.PPC_evsli

PPC_evsplatie = _ida_allins.PPC_evsplatie

PPC_evsplatib = _ida_allins.PPC_evsplatib

PPC_evsplatibe = _ida_allins.PPC_evsplatibe

PPC_evsplatih = _ida_allins.PPC_evsplatih

PPC_evsplatihe = _ida_allins.PPC_evsplatihe

PPC_evsplatid = _ida_allins.PPC_evsplatid

PPC_evsplatia = _ida_allins.PPC_evsplatia

PPC_evsplatiea = _ida_allins.PPC_evsplatiea

PPC_evsplatiba = _ida_allins.PPC_evsplatiba

PPC_evsplatibea = _ida_allins.PPC_evsplatibea

PPC_evsplatiha = _ida_allins.PPC_evsplatiha

PPC_evsplatihea = _ida_allins.PPC_evsplatihea

PPC_evsplatida = _ida_allins.PPC_evsplatida

PPC_evsplatfio = _ida_allins.PPC_evsplatfio

PPC_evsplatfib = _ida_allins.PPC_evsplatfib

PPC_evsplatfibo = _ida_allins.PPC_evsplatfibo

PPC_evsplatfih = _ida_allins.PPC_evsplatfih

PPC_evsplatfiho = _ida_allins.PPC_evsplatfiho

PPC_evsplatfid = _ida_allins.PPC_evsplatfid

PPC_evsplatfia = _ida_allins.PPC_evsplatfia

PPC_evsplatfioa = _ida_allins.PPC_evsplatfioa

PPC_evsplatfiba = _ida_allins.PPC_evsplatfiba

PPC_evsplatfiboa = _ida_allins.PPC_evsplatfiboa

PPC_evsplatfiha = _ida_allins.PPC_evsplatfiha

PPC_evsplatfihoa = _ida_allins.PPC_evsplatfihoa

PPC_evsplatfida = _ida_allins.PPC_evsplatfida

PPC_evcmpgtdu = _ida_allins.PPC_evcmpgtdu

PPC_evcmpgtds = _ida_allins.PPC_evcmpgtds

PPC_evcmpltdu = _ida_allins.PPC_evcmpltdu

PPC_evcmpltds = _ida_allins.PPC_evcmpltds

PPC_evcmpeqd = _ida_allins.PPC_evcmpeqd

PPC_evswapbhilo = _ida_allins.PPC_evswapbhilo

PPC_evswapblohi = _ida_allins.PPC_evswapblohi

PPC_evswaphhilo = _ida_allins.PPC_evswaphhilo

PPC_evswaphlohi = _ida_allins.PPC_evswaphlohi

PPC_evswaphe = _ida_allins.PPC_evswaphe

PPC_evswaphhi = _ida_allins.PPC_evswaphhi

PPC_evswaphlo = _ida_allins.PPC_evswaphlo

PPC_evswapho = _ida_allins.PPC_evswapho

PPC_evinsb = _ida_allins.PPC_evinsb

PPC_evxtrb = _ida_allins.PPC_evxtrb

PPC_evsplath = _ida_allins.PPC_evsplath

PPC_evsplatb = _ida_allins.PPC_evsplatb

PPC_evinsh = _ida_allins.PPC_evinsh

PPC_evclrbe = _ida_allins.PPC_evclrbe

PPC_evclrbo = _ida_allins.PPC_evclrbo

PPC_evxtrh = _ida_allins.PPC_evxtrh

PPC_evclrh = _ida_allins.PPC_evclrh

PPC_evselbitm0 = _ida_allins.PPC_evselbitm0

PPC_evselbitm1 = _ida_allins.PPC_evselbitm1

PPC_evselbit = _ida_allins.PPC_evselbit

PPC_evperm = _ida_allins.PPC_evperm

PPC_evperm2 = _ida_allins.PPC_evperm2

PPC_evperm3 = _ida_allins.PPC_evperm3

PPC_evxtrd = _ida_allins.PPC_evxtrd

PPC_evsrbu = _ida_allins.PPC_evsrbu

PPC_evsrbs = _ida_allins.PPC_evsrbs

PPC_evsrbiu = _ida_allins.PPC_evsrbiu

PPC_evsrbis = _ida_allins.PPC_evsrbis

PPC_evslb = _ida_allins.PPC_evslb

PPC_evrlb = _ida_allins.PPC_evrlb

PPC_evslbi = _ida_allins.PPC_evslbi

PPC_evrlbi = _ida_allins.PPC_evrlbi

PPC_evsrhu = _ida_allins.PPC_evsrhu

PPC_evsrhs = _ida_allins.PPC_evsrhs

PPC_evsrhiu = _ida_allins.PPC_evsrhiu

PPC_evsrhis = _ida_allins.PPC_evsrhis

PPC_evslh = _ida_allins.PPC_evslh

PPC_evrlh = _ida_allins.PPC_evrlh

PPC_evslhi = _ida_allins.PPC_evslhi

PPC_evrlhi = _ida_allins.PPC_evrlhi

PPC_evsru = _ida_allins.PPC_evsru

PPC_evsrs = _ida_allins.PPC_evsrs

PPC_evsriu = _ida_allins.PPC_evsriu

PPC_evsris = _ida_allins.PPC_evsris

PPC_evlvsl = _ida_allins.PPC_evlvsl

PPC_evlvsr = _ida_allins.PPC_evlvsr

PPC_evsroiu = _ida_allins.PPC_evsroiu

PPC_evsloi = _ida_allins.PPC_evsloi

PPC_evsrois = _ida_allins.PPC_evsrois

PPC_evldbx = _ida_allins.PPC_evldbx

PPC_evldb = _ida_allins.PPC_evldb

PPC_evlhhsplathx = _ida_allins.PPC_evlhhsplathx

PPC_evlhhsplath = _ida_allins.PPC_evlhhsplath

PPC_evlwbsplatwx = _ida_allins.PPC_evlwbsplatwx

PPC_evlwbsplatw = _ida_allins.PPC_evlwbsplatw

PPC_evlwhsplatwx = _ida_allins.PPC_evlwhsplatwx

PPC_evlwhsplatw = _ida_allins.PPC_evlwhsplatw

PPC_evlbbsplatbx = _ida_allins.PPC_evlbbsplatbx

PPC_evlbbsplatb = _ida_allins.PPC_evlbbsplatb

PPC_evstdbx = _ida_allins.PPC_evstdbx

PPC_evstdb = _ida_allins.PPC_evstdb

PPC_evlwbex = _ida_allins.PPC_evlwbex

PPC_evlwbe = _ida_allins.PPC_evlwbe

PPC_evlwboux = _ida_allins.PPC_evlwboux

PPC_evlwbou = _ida_allins.PPC_evlwbou

PPC_evlwbosx = _ida_allins.PPC_evlwbosx

PPC_evlwbos = _ida_allins.PPC_evlwbos

PPC_evstwbex = _ida_allins.PPC_evstwbex

PPC_evstwbe = _ida_allins.PPC_evstwbe

PPC_evstwbox = _ida_allins.PPC_evstwbox

PPC_evstwbo = _ida_allins.PPC_evstwbo

PPC_evstwbx = _ida_allins.PPC_evstwbx

PPC_evstwb = _ida_allins.PPC_evstwb

PPC_evsthbx = _ida_allins.PPC_evsthbx

PPC_evsthb = _ida_allins.PPC_evsthb

PPC_evlddmx = _ida_allins.PPC_evlddmx

PPC_evlddu = _ida_allins.PPC_evlddu

PPC_evldwmx = _ida_allins.PPC_evldwmx

PPC_evldwu = _ida_allins.PPC_evldwu

PPC_evldhmx = _ida_allins.PPC_evldhmx

PPC_evldhu = _ida_allins.PPC_evldhu

PPC_evldbmx = _ida_allins.PPC_evldbmx

PPC_evldbu = _ida_allins.PPC_evldbu

PPC_evlhhesplatmx = _ida_allins.PPC_evlhhesplatmx

PPC_evlhhesplatu = _ida_allins.PPC_evlhhesplatu

PPC_evlhhsplathmx = _ida_allins.PPC_evlhhsplathmx

PPC_evlhhsplathu = _ida_allins.PPC_evlhhsplathu

PPC_evlhhousplatmx = _ida_allins.PPC_evlhhousplatmx

PPC_evlhhousplatu = _ida_allins.PPC_evlhhousplatu

PPC_evlhhossplatmx = _ida_allins.PPC_evlhhossplatmx

PPC_evlhhossplatu = _ida_allins.PPC_evlhhossplatu

PPC_evlwhemx = _ida_allins.PPC_evlwhemx

PPC_evlwheu = _ida_allins.PPC_evlwheu

PPC_evlwbsplatwmx = _ida_allins.PPC_evlwbsplatwmx

PPC_evlwbsplatwu = _ida_allins.PPC_evlwbsplatwu

PPC_evlwhoumx = _ida_allins.PPC_evlwhoumx

PPC_evlwhouu = _ida_allins.PPC_evlwhouu

PPC_evlwhosmx = _ida_allins.PPC_evlwhosmx

PPC_evlwhosu = _ida_allins.PPC_evlwhosu

PPC_evlwwsplatmx = _ida_allins.PPC_evlwwsplatmx

PPC_evlwwsplatu = _ida_allins.PPC_evlwwsplatu

PPC_evlwhsplatwmx = _ida_allins.PPC_evlwhsplatwmx

PPC_evlwhsplatwu = _ida_allins.PPC_evlwhsplatwu

PPC_evlwhsplatmx = _ida_allins.PPC_evlwhsplatmx

PPC_evlwhsplatu = _ida_allins.PPC_evlwhsplatu

PPC_evlbbsplatbmx = _ida_allins.PPC_evlbbsplatbmx

PPC_evlbbsplatbu = _ida_allins.PPC_evlbbsplatbu

PPC_evstddmx = _ida_allins.PPC_evstddmx

PPC_evstddu = _ida_allins.PPC_evstddu

PPC_evstdwmx = _ida_allins.PPC_evstdwmx

PPC_evstdwu = _ida_allins.PPC_evstdwu

PPC_evstdhmx = _ida_allins.PPC_evstdhmx

PPC_evstdhu = _ida_allins.PPC_evstdhu

PPC_evstdbmx = _ida_allins.PPC_evstdbmx

PPC_evstdbu = _ida_allins.PPC_evstdbu

PPC_evlwbemx = _ida_allins.PPC_evlwbemx

PPC_evlwbeu = _ida_allins.PPC_evlwbeu

PPC_evlwboumx = _ida_allins.PPC_evlwboumx

PPC_evlwbouu = _ida_allins.PPC_evlwbouu

PPC_evlwbosmx = _ida_allins.PPC_evlwbosmx

PPC_evlwbosu = _ida_allins.PPC_evlwbosu

PPC_evstwhemx = _ida_allins.PPC_evstwhemx

PPC_evstwheu = _ida_allins.PPC_evstwheu

PPC_evstwbemx = _ida_allins.PPC_evstwbemx

PPC_evstwbeu = _ida_allins.PPC_evstwbeu

PPC_evstwhomx = _ida_allins.PPC_evstwhomx

PPC_evstwhou = _ida_allins.PPC_evstwhou

PPC_evstwbomx = _ida_allins.PPC_evstwbomx

PPC_evstwbou = _ida_allins.PPC_evstwbou

PPC_evstwwemx = _ida_allins.PPC_evstwwemx

PPC_evstwweu = _ida_allins.PPC_evstwweu

PPC_evstwbmx = _ida_allins.PPC_evstwbmx

PPC_evstwbu = _ida_allins.PPC_evstwbu

PPC_evstwwomx = _ida_allins.PPC_evstwwomx

PPC_evstwwou = _ida_allins.PPC_evstwwou

PPC_evsthbmx = _ida_allins.PPC_evsthbmx

PPC_evsthbu = _ida_allins.PPC_evsthbu

PPC_evmhusi = _ida_allins.PPC_evmhusi

PPC_evmhssi = _ida_allins.PPC_evmhssi

PPC_evmhsusi = _ida_allins.PPC_evmhsusi

PPC_evmhssf = _ida_allins.PPC_evmhssf

PPC_evmhumi = _ida_allins.PPC_evmhumi

PPC_evmhssfr = _ida_allins.PPC_evmhssfr

PPC_evmhesumi = _ida_allins.PPC_evmhesumi

PPC_evmhosumi = _ida_allins.PPC_evmhosumi

PPC_evmbeumi = _ida_allins.PPC_evmbeumi

PPC_evmbesmi = _ida_allins.PPC_evmbesmi

PPC_evmbesumi = _ida_allins.PPC_evmbesumi

PPC_evmboumi = _ida_allins.PPC_evmboumi

PPC_evmbosmi = _ida_allins.PPC_evmbosmi

PPC_evmbosumi = _ida_allins.PPC_evmbosumi

PPC_evmhesumia = _ida_allins.PPC_evmhesumia

PPC_evmhosumia = _ida_allins.PPC_evmhosumia

PPC_evmbeumia = _ida_allins.PPC_evmbeumia

PPC_evmbesmia = _ida_allins.PPC_evmbesmia

PPC_evmbesumia = _ida_allins.PPC_evmbesumia

PPC_evmboumia = _ida_allins.PPC_evmboumia

PPC_evmbosmia = _ida_allins.PPC_evmbosmia

PPC_evmbosumia = _ida_allins.PPC_evmbosumia

PPC_evmwusiw = _ida_allins.PPC_evmwusiw

PPC_evmwssiw = _ida_allins.PPC_evmwssiw

PPC_evmwhssfr = _ida_allins.PPC_evmwhssfr

PPC_evmwehgsmfr = _ida_allins.PPC_evmwehgsmfr

PPC_evmwehgsmf = _ida_allins.PPC_evmwehgsmf

PPC_evmwohgsmfr = _ida_allins.PPC_evmwohgsmfr

PPC_evmwohgsmf = _ida_allins.PPC_evmwohgsmf

PPC_evmwhssfra = _ida_allins.PPC_evmwhssfra

PPC_evmwehgsmfra = _ida_allins.PPC_evmwehgsmfra

PPC_evmwehgsmfa = _ida_allins.PPC_evmwehgsmfa

PPC_evmwohgsmfra = _ida_allins.PPC_evmwohgsmfra

PPC_evmwohgsmfa = _ida_allins.PPC_evmwohgsmfa

PPC_evaddusiaa = _ida_allins.PPC_evaddusiaa

PPC_evaddssiaa = _ida_allins.PPC_evaddssiaa

PPC_evsubfusiaa = _ida_allins.PPC_evsubfusiaa

PPC_evsubfssiaa = _ida_allins.PPC_evsubfssiaa

PPC_evaddsmiaa = _ida_allins.PPC_evaddsmiaa

PPC_evsubfsmiaa = _ida_allins.PPC_evsubfsmiaa

PPC_evaddh = _ida_allins.PPC_evaddh

PPC_evaddhss = _ida_allins.PPC_evaddhss

PPC_evsubfh = _ida_allins.PPC_evsubfh

PPC_evsubfhss = _ida_allins.PPC_evsubfhss

PPC_evaddhx = _ida_allins.PPC_evaddhx

PPC_evaddhxss = _ida_allins.PPC_evaddhxss

PPC_evsubfhx = _ida_allins.PPC_evsubfhx

PPC_evsubfhxss = _ida_allins.PPC_evsubfhxss

PPC_evaddd = _ida_allins.PPC_evaddd

PPC_evadddss = _ida_allins.PPC_evadddss

PPC_evsubfd = _ida_allins.PPC_evsubfd

PPC_evsubfdss = _ida_allins.PPC_evsubfdss

PPC_evaddb = _ida_allins.PPC_evaddb

PPC_evaddbss = _ida_allins.PPC_evaddbss

PPC_evsubfb = _ida_allins.PPC_evsubfb

PPC_evsubfbss = _ida_allins.PPC_evsubfbss

PPC_evaddsubfh = _ida_allins.PPC_evaddsubfh

PPC_evaddsubfhss = _ida_allins.PPC_evaddsubfhss

PPC_evsubfaddh = _ida_allins.PPC_evsubfaddh

PPC_evsubfaddhss = _ida_allins.PPC_evsubfaddhss

PPC_evaddsubfhx = _ida_allins.PPC_evaddsubfhx

PPC_evaddsubfhxss = _ida_allins.PPC_evaddsubfhxss

PPC_evsubfaddhx = _ida_allins.PPC_evsubfaddhx

PPC_evsubfaddhxss = _ida_allins.PPC_evsubfaddhxss

PPC_evadddus = _ida_allins.PPC_evadddus

PPC_evaddbus = _ida_allins.PPC_evaddbus

PPC_evsubfdus = _ida_allins.PPC_evsubfdus

PPC_evsubfbus = _ida_allins.PPC_evsubfbus

PPC_evaddwus = _ida_allins.PPC_evaddwus

PPC_evaddwxus = _ida_allins.PPC_evaddwxus

PPC_evsubfwus = _ida_allins.PPC_evsubfwus

PPC_evsubfwxus = _ida_allins.PPC_evsubfwxus

PPC_evadd2subf2h = _ida_allins.PPC_evadd2subf2h

PPC_evadd2subf2hss = _ida_allins.PPC_evadd2subf2hss

PPC_evsubf2add2h = _ida_allins.PPC_evsubf2add2h

PPC_evsubf2add2hss = _ida_allins.PPC_evsubf2add2hss

PPC_evaddhus = _ida_allins.PPC_evaddhus

PPC_evaddhxus = _ida_allins.PPC_evaddhxus

PPC_evsubfhus = _ida_allins.PPC_evsubfhus

PPC_evsubfhxus = _ida_allins.PPC_evsubfhxus

PPC_evaddwss = _ida_allins.PPC_evaddwss

PPC_evsubfwss = _ida_allins.PPC_evsubfwss

PPC_evaddwx = _ida_allins.PPC_evaddwx

PPC_evaddwxss = _ida_allins.PPC_evaddwxss

PPC_evsubfwx = _ida_allins.PPC_evsubfwx

PPC_evsubfwxss = _ida_allins.PPC_evsubfwxss

PPC_evaddsubfw = _ida_allins.PPC_evaddsubfw

PPC_evaddsubfwss = _ida_allins.PPC_evaddsubfwss

PPC_evsubfaddw = _ida_allins.PPC_evsubfaddw

PPC_evsubfaddwss = _ida_allins.PPC_evsubfaddwss

PPC_evaddsubfwx = _ida_allins.PPC_evaddsubfwx

PPC_evaddsubfwxss = _ida_allins.PPC_evaddsubfwxss

PPC_evsubfaddwx = _ida_allins.PPC_evsubfaddwx

PPC_evsubfaddwxss = _ida_allins.PPC_evsubfaddwxss

PPC_evmar = _ida_allins.PPC_evmar

PPC_evsumwu = _ida_allins.PPC_evsumwu

PPC_evsumws = _ida_allins.PPC_evsumws

PPC_evsum4bu = _ida_allins.PPC_evsum4bu

PPC_evsum4bs = _ida_allins.PPC_evsum4bs

PPC_evsum2hu = _ida_allins.PPC_evsum2hu

PPC_evsum2hs = _ida_allins.PPC_evsum2hs

PPC_evdiff2his = _ida_allins.PPC_evdiff2his

PPC_evsum2his = _ida_allins.PPC_evsum2his

PPC_evsumwua = _ida_allins.PPC_evsumwua

PPC_evsumwsa = _ida_allins.PPC_evsumwsa

PPC_evsum4bua = _ida_allins.PPC_evsum4bua

PPC_evsum4bsa = _ida_allins.PPC_evsum4bsa

PPC_evsum2hua = _ida_allins.PPC_evsum2hua

PPC_evsum2hsa = _ida_allins.PPC_evsum2hsa

PPC_evdiff2hisa = _ida_allins.PPC_evdiff2hisa

PPC_evsum2hisa = _ida_allins.PPC_evsum2hisa

PPC_evsumwuaa = _ida_allins.PPC_evsumwuaa

PPC_evsumwsaa = _ida_allins.PPC_evsumwsaa

PPC_evsum4buaaw = _ida_allins.PPC_evsum4buaaw

PPC_evsum4bsaaw = _ida_allins.PPC_evsum4bsaaw

PPC_evsum2huaaw = _ida_allins.PPC_evsum2huaaw

PPC_evsum2hsaaw = _ida_allins.PPC_evsum2hsaaw

PPC_evdiff2hisaaw = _ida_allins.PPC_evdiff2hisaaw

PPC_evsum2hisaaw = _ida_allins.PPC_evsum2hisaaw

PPC_evdivwsf = _ida_allins.PPC_evdivwsf

PPC_evdivwuf = _ida_allins.PPC_evdivwuf

PPC_evdivs = _ida_allins.PPC_evdivs

PPC_evdivu = _ida_allins.PPC_evdivu

PPC_evaddwegsi = _ida_allins.PPC_evaddwegsi

PPC_evaddwegsf = _ida_allins.PPC_evaddwegsf

PPC_evsubfwegsi = _ida_allins.PPC_evsubfwegsi

PPC_evsubfwegsf = _ida_allins.PPC_evsubfwegsf

PPC_evaddwogsi = _ida_allins.PPC_evaddwogsi

PPC_evaddwogsf = _ida_allins.PPC_evaddwogsf

PPC_evsubfwogsi = _ida_allins.PPC_evsubfwogsi

PPC_evsubfwogsf = _ida_allins.PPC_evsubfwogsf

PPC_evaddhhiuw = _ida_allins.PPC_evaddhhiuw

PPC_evaddhhisw = _ida_allins.PPC_evaddhhisw

PPC_evsubfhhiuw = _ida_allins.PPC_evsubfhhiuw

PPC_evsubfhhisw = _ida_allins.PPC_evsubfhhisw

PPC_evaddhlouw = _ida_allins.PPC_evaddhlouw

PPC_evaddhlosw = _ida_allins.PPC_evaddhlosw

PPC_evsubfhlouw = _ida_allins.PPC_evsubfhlouw

PPC_evsubfhlosw = _ida_allins.PPC_evsubfhlosw

PPC_evmhesusiaaw = _ida_allins.PPC_evmhesusiaaw

PPC_evmhosusiaaw = _ida_allins.PPC_evmhosusiaaw

PPC_evmhesumiaaw = _ida_allins.PPC_evmhesumiaaw

PPC_evmhosumiaaw = _ida_allins.PPC_evmhosumiaaw

PPC_evmbeusiaah = _ida_allins.PPC_evmbeusiaah

PPC_evmbessiaah = _ida_allins.PPC_evmbessiaah

PPC_evmbesusiaah = _ida_allins.PPC_evmbesusiaah

PPC_evmbousiaah = _ida_allins.PPC_evmbousiaah

PPC_evmbossiaah = _ida_allins.PPC_evmbossiaah

PPC_evmbosusiaah = _ida_allins.PPC_evmbosusiaah

PPC_evmbeumiaah = _ida_allins.PPC_evmbeumiaah

PPC_evmbesmiaah = _ida_allins.PPC_evmbesmiaah

PPC_evmbesumiaah = _ida_allins.PPC_evmbesumiaah

PPC_evmboumiaah = _ida_allins.PPC_evmboumiaah

PPC_evmbosmiaah = _ida_allins.PPC_evmbosmiaah

PPC_evmbosumiaah = _ida_allins.PPC_evmbosumiaah

PPC_evmwlusiaaw3 = _ida_allins.PPC_evmwlusiaaw3

PPC_evmwlssiaaw3 = _ida_allins.PPC_evmwlssiaaw3

PPC_evmwhssfraaw3 = _ida_allins.PPC_evmwhssfraaw3

PPC_evmwhssfaaw3 = _ida_allins.PPC_evmwhssfaaw3

PPC_evmwhssfraaw = _ida_allins.PPC_evmwhssfraaw

PPC_evmwhssfaaw = _ida_allins.PPC_evmwhssfaaw

PPC_evmwlumiaaw3 = _ida_allins.PPC_evmwlumiaaw3

PPC_evmwlsmiaaw3 = _ida_allins.PPC_evmwlsmiaaw3

PPC_evmwusiaa = _ida_allins.PPC_evmwusiaa

PPC_evmwssiaa = _ida_allins.PPC_evmwssiaa

PPC_evmwehgsmfraa = _ida_allins.PPC_evmwehgsmfraa

PPC_evmwehgsmfaa = _ida_allins.PPC_evmwehgsmfaa

PPC_evmwohgsmfraa = _ida_allins.PPC_evmwohgsmfraa

PPC_evmwohgsmfaa = _ida_allins.PPC_evmwohgsmfaa

PPC_evmhesusianw = _ida_allins.PPC_evmhesusianw

PPC_evmhosusianw = _ida_allins.PPC_evmhosusianw

PPC_evmhesumianw = _ida_allins.PPC_evmhesumianw

PPC_evmhosumianw = _ida_allins.PPC_evmhosumianw

PPC_evmbeusianh = _ida_allins.PPC_evmbeusianh

PPC_evmbessianh = _ida_allins.PPC_evmbessianh

PPC_evmbesusianh = _ida_allins.PPC_evmbesusianh

PPC_evmbousianh = _ida_allins.PPC_evmbousianh

PPC_evmbossianh = _ida_allins.PPC_evmbossianh

PPC_evmbosusianh = _ida_allins.PPC_evmbosusianh

PPC_evmbeumianh = _ida_allins.PPC_evmbeumianh

PPC_evmbesmianh = _ida_allins.PPC_evmbesmianh

PPC_evmbesumianh = _ida_allins.PPC_evmbesumianh

PPC_evmboumianh = _ida_allins.PPC_evmboumianh

PPC_evmbosmianh = _ida_allins.PPC_evmbosmianh

PPC_evmbosumianh = _ida_allins.PPC_evmbosumianh

PPC_evmwlusianw3 = _ida_allins.PPC_evmwlusianw3

PPC_evmwlssianw3 = _ida_allins.PPC_evmwlssianw3

PPC_evmwhssfranw3 = _ida_allins.PPC_evmwhssfranw3

PPC_evmwhssfanw3 = _ida_allins.PPC_evmwhssfanw3

PPC_evmwhssfranw = _ida_allins.PPC_evmwhssfranw

PPC_evmwhssfanw = _ida_allins.PPC_evmwhssfanw

PPC_evmwlumianw3 = _ida_allins.PPC_evmwlumianw3

PPC_evmwlsmianw3 = _ida_allins.PPC_evmwlsmianw3

PPC_evmwusian = _ida_allins.PPC_evmwusian

PPC_evmwssian = _ida_allins.PPC_evmwssian

PPC_evmwehgsmfran = _ida_allins.PPC_evmwehgsmfran

PPC_evmwehgsmfan = _ida_allins.PPC_evmwehgsmfan

PPC_evmwohgsmfran = _ida_allins.PPC_evmwohgsmfran

PPC_evmwohgsmfan = _ida_allins.PPC_evmwohgsmfan

PPC_evseteqb = _ida_allins.PPC_evseteqb

PPC_evseteqh = _ida_allins.PPC_evseteqh

PPC_evseteqw = _ida_allins.PPC_evseteqw

PPC_evsetgthu = _ida_allins.PPC_evsetgthu

PPC_evsetgths = _ida_allins.PPC_evsetgths

PPC_evsetgtwu = _ida_allins.PPC_evsetgtwu

PPC_evsetgtws = _ida_allins.PPC_evsetgtws

PPC_evsetgtbu = _ida_allins.PPC_evsetgtbu

PPC_evsetgtbs = _ida_allins.PPC_evsetgtbs

PPC_evsetltbu = _ida_allins.PPC_evsetltbu

PPC_evsetltbs = _ida_allins.PPC_evsetltbs

PPC_evsetlthu = _ida_allins.PPC_evsetlthu

PPC_evsetlths = _ida_allins.PPC_evsetlths

PPC_evsetltwu = _ida_allins.PPC_evsetltwu

PPC_evsetltws = _ida_allins.PPC_evsetltws

PPC_evsaduw = _ida_allins.PPC_evsaduw

PPC_evsadsw = _ida_allins.PPC_evsadsw

PPC_evsad4ub = _ida_allins.PPC_evsad4ub

PPC_evsad4sb = _ida_allins.PPC_evsad4sb

PPC_evsad2uh = _ida_allins.PPC_evsad2uh

PPC_evsad2sh = _ida_allins.PPC_evsad2sh

PPC_evsaduwa = _ida_allins.PPC_evsaduwa

PPC_evsadswa = _ida_allins.PPC_evsadswa

PPC_evsad4uba = _ida_allins.PPC_evsad4uba

PPC_evsad4sba = _ida_allins.PPC_evsad4sba

PPC_evsad2uha = _ida_allins.PPC_evsad2uha

PPC_evsad2sha = _ida_allins.PPC_evsad2sha

PPC_evabsdifuw = _ida_allins.PPC_evabsdifuw

PPC_evabsdifsw = _ida_allins.PPC_evabsdifsw

PPC_evabsdifub = _ida_allins.PPC_evabsdifub

PPC_evabsdifsb = _ida_allins.PPC_evabsdifsb

PPC_evabsdifuh = _ida_allins.PPC_evabsdifuh

PPC_evabsdifsh = _ida_allins.PPC_evabsdifsh

PPC_evsaduwaa = _ida_allins.PPC_evsaduwaa

PPC_evsadswaa = _ida_allins.PPC_evsadswaa

PPC_evsad4ubaaw = _ida_allins.PPC_evsad4ubaaw

PPC_evsad4sbaaw = _ida_allins.PPC_evsad4sbaaw

PPC_evsad2uhaaw = _ida_allins.PPC_evsad2uhaaw

PPC_evsad2shaaw = _ida_allins.PPC_evsad2shaaw

PPC_evpkshubs = _ida_allins.PPC_evpkshubs

PPC_evpkshsbs = _ida_allins.PPC_evpkshsbs

PPC_evpkswuhs = _ida_allins.PPC_evpkswuhs

PPC_evpkswshs = _ida_allins.PPC_evpkswshs

PPC_evpkuhubs = _ida_allins.PPC_evpkuhubs

PPC_evpkuwuhs = _ida_allins.PPC_evpkuwuhs

PPC_evpkswshilvs = _ida_allins.PPC_evpkswshilvs

PPC_evpkswgshefrs = _ida_allins.PPC_evpkswgshefrs

PPC_evpkswshfrs = _ida_allins.PPC_evpkswshfrs

PPC_evpkswshilvfrs = _ida_allins.PPC_evpkswshilvfrs

PPC_evpksdswfrs = _ida_allins.PPC_evpksdswfrs

PPC_evpksdshefrs = _ida_allins.PPC_evpksdshefrs

PPC_evpkuduws = _ida_allins.PPC_evpkuduws

PPC_evpksdsws = _ida_allins.PPC_evpksdsws

PPC_evpkswgswfrs = _ida_allins.PPC_evpkswgswfrs

PPC_evilveh = _ida_allins.PPC_evilveh

PPC_evilveoh = _ida_allins.PPC_evilveoh

PPC_evilvhih = _ida_allins.PPC_evilvhih

PPC_evilvhiloh = _ida_allins.PPC_evilvhiloh

PPC_evilvloh = _ida_allins.PPC_evilvloh

PPC_evilvlohih = _ida_allins.PPC_evilvlohih

PPC_evilvoeh = _ida_allins.PPC_evilvoeh

PPC_evilvoh = _ida_allins.PPC_evilvoh

PPC_evdlveb = _ida_allins.PPC_evdlveb

PPC_evdlveh = _ida_allins.PPC_evdlveh

PPC_evdlveob = _ida_allins.PPC_evdlveob

PPC_evdlveoh = _ida_allins.PPC_evdlveoh

PPC_evdlvob = _ida_allins.PPC_evdlvob

PPC_evdlvoh = _ida_allins.PPC_evdlvoh

PPC_evdlvoeb = _ida_allins.PPC_evdlvoeb

PPC_evdlvoeh = _ida_allins.PPC_evdlvoeh

PPC_evmaxbu = _ida_allins.PPC_evmaxbu

PPC_evmaxbs = _ida_allins.PPC_evmaxbs

PPC_evmaxhu = _ida_allins.PPC_evmaxhu

PPC_evmaxhs = _ida_allins.PPC_evmaxhs

PPC_evmaxwu = _ida_allins.PPC_evmaxwu

PPC_evmaxws = _ida_allins.PPC_evmaxws

PPC_evmaxdu = _ida_allins.PPC_evmaxdu

PPC_evmaxds = _ida_allins.PPC_evmaxds

PPC_evminbu = _ida_allins.PPC_evminbu

PPC_evminbs = _ida_allins.PPC_evminbs

PPC_evminhu = _ida_allins.PPC_evminhu

PPC_evminhs = _ida_allins.PPC_evminhs

PPC_evminwu = _ida_allins.PPC_evminwu

PPC_evminws = _ida_allins.PPC_evminws

PPC_evmindu = _ida_allins.PPC_evmindu

PPC_evminds = _ida_allins.PPC_evminds

PPC_evavgwu = _ida_allins.PPC_evavgwu

PPC_evavgws = _ida_allins.PPC_evavgws

PPC_evavgbu = _ida_allins.PPC_evavgbu

PPC_evavgbs = _ida_allins.PPC_evavgbs

PPC_evavghu = _ida_allins.PPC_evavghu

PPC_evavghs = _ida_allins.PPC_evavghs

PPC_evavgdu = _ida_allins.PPC_evavgdu

PPC_evavgds = _ida_allins.PPC_evavgds

PPC_evavgwur = _ida_allins.PPC_evavgwur

PPC_evavgwsr = _ida_allins.PPC_evavgwsr

PPC_evavgbur = _ida_allins.PPC_evavgbur

PPC_evavgbsr = _ida_allins.PPC_evavgbsr

PPC_evavghur = _ida_allins.PPC_evavghur

PPC_evavghsr = _ida_allins.PPC_evavghsr

PPC_evavgdur = _ida_allins.PPC_evavgdur

PPC_evavgdsr = _ida_allins.PPC_evavgdsr

PPC_tdui = _ida_allins.PPC_tdui

PPC_tdu = _ida_allins.PPC_tdu

PPC_twui = _ida_allins.PPC_twui

PPC_twu = _ida_allins.PPC_twu

PPC_bctar = _ida_allins.PPC_bctar

PPC_clrbhrb = _ida_allins.PPC_clrbhrb

PPC_mfbhrbe = _ida_allins.PPC_mfbhrbe

PPC_mtsle = _ida_allins.PPC_mtsle

PPC_mfvsrd = _ida_allins.PPC_mfvsrd

PPC_mfvsrwz = _ida_allins.PPC_mfvsrwz

PPC_mtvsrd = _ida_allins.PPC_mtvsrd

PPC_mtvsrwa = _ida_allins.PPC_mtvsrwa

PPC_mtvsrwz = _ida_allins.PPC_mtvsrwz

PPC_fmrgew = _ida_allins.PPC_fmrgew

PPC_fmrgow = _ida_allins.PPC_fmrgow

PPC_vpksdss = _ida_allins.PPC_vpksdss

PPC_vpksdus = _ida_allins.PPC_vpksdus

PPC_vpkudus = _ida_allins.PPC_vpkudus

PPC_vpkudum = _ida_allins.PPC_vpkudum

PPC_vupkhsw = _ida_allins.PPC_vupkhsw

PPC_vupklsw = _ida_allins.PPC_vupklsw

PPC_vmrgew = _ida_allins.PPC_vmrgew

PPC_vmrgow = _ida_allins.PPC_vmrgow

PPC_vaddudm = _ida_allins.PPC_vaddudm

PPC_vadduqm = _ida_allins.PPC_vadduqm

PPC_vaddeuqm = _ida_allins.PPC_vaddeuqm

PPC_vaddcuq = _ida_allins.PPC_vaddcuq

PPC_vaddecuq = _ida_allins.PPC_vaddecuq

PPC_vsubudm = _ida_allins.PPC_vsubudm

PPC_vsubuqm = _ida_allins.PPC_vsubuqm

PPC_vsubeuqm = _ida_allins.PPC_vsubeuqm

PPC_vsubcuq = _ida_allins.PPC_vsubcuq

PPC_vsubecuq = _ida_allins.PPC_vsubecuq

PPC_vmulesw = _ida_allins.PPC_vmulesw

PPC_vmuleuw = _ida_allins.PPC_vmuleuw

PPC_vmulosw = _ida_allins.PPC_vmulosw

PPC_vmulouw = _ida_allins.PPC_vmulouw

PPC_vmuluwm = _ida_allins.PPC_vmuluwm

PPC_vmaxsd = _ida_allins.PPC_vmaxsd

PPC_vmaxud = _ida_allins.PPC_vmaxud

PPC_vminsd = _ida_allins.PPC_vminsd

PPC_vminud = _ida_allins.PPC_vminud

PPC_vcmpequd = _ida_allins.PPC_vcmpequd

PPC_vcmpgtsd = _ida_allins.PPC_vcmpgtsd

PPC_vcmpgtud = _ida_allins.PPC_vcmpgtud

PPC_veqv = _ida_allins.PPC_veqv

PPC_vnand = _ida_allins.PPC_vnand

PPC_vorc = _ida_allins.PPC_vorc

PPC_vrld = _ida_allins.PPC_vrld

PPC_vsld = _ida_allins.PPC_vsld

PPC_vsrd = _ida_allins.PPC_vsrd

PPC_vsrad = _ida_allins.PPC_vsrad

PPC_vcipher = _ida_allins.PPC_vcipher

PPC_vcipherlast = _ida_allins.PPC_vcipherlast

PPC_vncipher = _ida_allins.PPC_vncipher

PPC_vncipherlast = _ida_allins.PPC_vncipherlast

PPC_vsbox = _ida_allins.PPC_vsbox

PPC_vshasigmad = _ida_allins.PPC_vshasigmad

PPC_vshasigmaw = _ida_allins.PPC_vshasigmaw

PPC_vpmsumb = _ida_allins.PPC_vpmsumb

PPC_vpmsumd = _ida_allins.PPC_vpmsumd

PPC_vpmsumh = _ida_allins.PPC_vpmsumh

PPC_vpmsumw = _ida_allins.PPC_vpmsumw

PPC_vpermxor = _ida_allins.PPC_vpermxor

PPC_vgbbd = _ida_allins.PPC_vgbbd

PPC_vclzb = _ida_allins.PPC_vclzb

PPC_vclzh = _ida_allins.PPC_vclzh

PPC_vclzw = _ida_allins.PPC_vclzw

PPC_vclzd = _ida_allins.PPC_vclzd

PPC_vpopcntb = _ida_allins.PPC_vpopcntb

PPC_vpopcntd = _ida_allins.PPC_vpopcntd

PPC_vpopcnth = _ida_allins.PPC_vpopcnth

PPC_vpopcntw = _ida_allins.PPC_vpopcntw

PPC_vbpermq = _ida_allins.PPC_vbpermq

PPC_bcdadd = _ida_allins.PPC_bcdadd

PPC_bcdsub = _ida_allins.PPC_bcdsub

PPC_lxsiwax = _ida_allins.PPC_lxsiwax

PPC_lxsspx = _ida_allins.PPC_lxsspx

PPC_lxsiwzx = _ida_allins.PPC_lxsiwzx

PPC_stxsiwx = _ida_allins.PPC_stxsiwx

PPC_stxsspx = _ida_allins.PPC_stxsspx

PPC_xsaddsp = _ida_allins.PPC_xsaddsp

PPC_xscvdpspn = _ida_allins.PPC_xscvdpspn

PPC_xscvspdpn = _ida_allins.PPC_xscvspdpn

PPC_xscvsxdsp = _ida_allins.PPC_xscvsxdsp

PPC_xscvuxdsp = _ida_allins.PPC_xscvuxdsp

PPC_xsdivsp = _ida_allins.PPC_xsdivsp

PPC_xsmaddasp = _ida_allins.PPC_xsmaddasp

PPC_xsmaddmsp = _ida_allins.PPC_xsmaddmsp

PPC_xsmsubasp = _ida_allins.PPC_xsmsubasp

PPC_xsmsubmsp = _ida_allins.PPC_xsmsubmsp

PPC_xsmulsp = _ida_allins.PPC_xsmulsp

PPC_xsnmaddasp = _ida_allins.PPC_xsnmaddasp

PPC_xsnmaddmsp = _ida_allins.PPC_xsnmaddmsp

PPC_xsnmsubasp = _ida_allins.PPC_xsnmsubasp

PPC_xsnmsubmsp = _ida_allins.PPC_xsnmsubmsp

PPC_xsresp = _ida_allins.PPC_xsresp

PPC_xsrsp = _ida_allins.PPC_xsrsp

PPC_xsrsqrtesp = _ida_allins.PPC_xsrsqrtesp

PPC_xssqrtsp = _ida_allins.PPC_xssqrtsp

PPC_xssubsp = _ida_allins.PPC_xssubsp

PPC_xxleqv = _ida_allins.PPC_xxleqv

PPC_xxlnand = _ida_allins.PPC_xxlnand

PPC_xxlorc = _ida_allins.PPC_xxlorc

PPC_lqarx = _ida_allins.PPC_lqarx

PPC_stqcx = _ida_allins.PPC_stqcx

PPC_tbegin = _ida_allins.PPC_tbegin

PPC_tend = _ida_allins.PPC_tend

PPC_tabort = _ida_allins.PPC_tabort

PPC_tabortwc = _ida_allins.PPC_tabortwc

PPC_tabortwci = _ida_allins.PPC_tabortwci

PPC_tabortdc = _ida_allins.PPC_tabortdc

PPC_tabortdci = _ida_allins.PPC_tabortdci

PPC_tsr = _ida_allins.PPC_tsr

PPC_tcheck = _ida_allins.PPC_tcheck

PPC_rfebb = _ida_allins.PPC_rfebb

PPC_treclaim = _ida_allins.PPC_treclaim

PPC_trechkpt = _ida_allins.PPC_trechkpt

PPC_msgsndp = _ida_allins.PPC_msgsndp

PPC_msgclrp = _ida_allins.PPC_msgclrp

PPC_dcblq = _ida_allins.PPC_dcblq

PPC_icblq = _ida_allins.PPC_icblq

PPC_vmr = _ida_allins.PPC_vmr

PPC_vnot = _ida_allins.PPC_vnot

PPC_tendall = _ida_allins.PPC_tendall

PPC_tsuspend = _ida_allins.PPC_tsuspend

PPC_tresume = _ida_allins.PPC_tresume

PPC_mtppr = _ida_allins.PPC_mtppr

PPC_mfppr = _ida_allins.PPC_mfppr

PPC_mtppr32 = _ida_allins.PPC_mtppr32

PPC_mfppr32 = _ida_allins.PPC_mfppr32

PPC_mtic = _ida_allins.PPC_mtic

PPC_mfic = _ida_allins.PPC_mfic

PPC_mtvtb = _ida_allins.PPC_mtvtb

PPC_mfvtb = _ida_allins.PPC_mfvtb

PPC_miso = _ida_allins.PPC_miso

PPC_mdoio = _ida_allins.PPC_mdoio

PPC_mdoom = _ida_allins.PPC_mdoom

PPC_yield = _ida_allins.PPC_yield

PPC_addbss = _ida_allins.PPC_addbss

PPC_addhss = _ida_allins.PPC_addhss

PPC_addwss = _ida_allins.PPC_addwss

PPC_addbus = _ida_allins.PPC_addbus

PPC_addhus = _ida_allins.PPC_addhus

PPC_addwus = _ida_allins.PPC_addwus

PPC_mulhss = _ida_allins.PPC_mulhss

PPC_mulwss = _ida_allins.PPC_mulwss

PPC_mulhus = _ida_allins.PPC_mulhus

PPC_mulwus = _ida_allins.PPC_mulwus

PPC_sat = _ida_allins.PPC_sat

PPC_subfbss = _ida_allins.PPC_subfbss

PPC_subfhss = _ida_allins.PPC_subfhss

PPC_subfwss = _ida_allins.PPC_subfwss

PPC_subfbus = _ida_allins.PPC_subfbus

PPC_subfhus = _ida_allins.PPC_subfhus

PPC_subfwus = _ida_allins.PPC_subfwus

PPC_satsbs = _ida_allins.PPC_satsbs

PPC_satubs = _ida_allins.PPC_satubs

PPC_satsbu = _ida_allins.PPC_satsbu

PPC_satubu = _ida_allins.PPC_satubu

PPC_abssb = _ida_allins.PPC_abssb

PPC_absub = _ida_allins.PPC_absub

PPC_satshs = _ida_allins.PPC_satshs

PPC_satuhs = _ida_allins.PPC_satuhs

PPC_satshu = _ida_allins.PPC_satshu

PPC_satuhu = _ida_allins.PPC_satuhu

PPC_abssh = _ida_allins.PPC_abssh

PPC_absuh = _ida_allins.PPC_absuh

PPC_satsws = _ida_allins.PPC_satsws

PPC_satuws = _ida_allins.PPC_satuws

PPC_satswu = _ida_allins.PPC_satswu

PPC_satuwu = _ida_allins.PPC_satuwu

PPC_abssw = _ida_allins.PPC_abssw

PPC_absuw = _ida_allins.PPC_absuw

PPC_dni = _ida_allins.PPC_dni

PPC_slbieg = _ida_allins.PPC_slbieg

PPC_slbiag = _ida_allins.PPC_slbiag

PPC_slbsync = _ida_allins.PPC_slbsync

PPC_addpcis = _ida_allins.PPC_addpcis

PPC_lnia = _ida_allins.PPC_lnia

PPC_subpcis = _ida_allins.PPC_subpcis

PPC_cmpeqb = _ida_allins.PPC_cmpeqb

PPC_cmprb = _ida_allins.PPC_cmprb

PPC_cnttzw = _ida_allins.PPC_cnttzw

PPC_cnttzd = _ida_allins.PPC_cnttzd

PPC_darn = _ida_allins.PPC_darn

PPC_extswsli = _ida_allins.PPC_extswsli

PPC_maddhd = _ida_allins.PPC_maddhd

PPC_maddhdu = _ida_allins.PPC_maddhdu

PPC_maddld = _ida_allins.PPC_maddld

PPC_mcrxrx = _ida_allins.PPC_mcrxrx

PPC_setb = _ida_allins.PPC_setb

PPC_modsd = _ida_allins.PPC_modsd

PPC_modud = _ida_allins.PPC_modud

PPC_modsw = _ida_allins.PPC_modsw

PPC_moduw = _ida_allins.PPC_moduw

PPC_mfvsrld = _ida_allins.PPC_mfvsrld

PPC_mtvsrdd = _ida_allins.PPC_mtvsrdd

PPC_mtvsrws = _ida_allins.PPC_mtvsrws

PPC_scv = _ida_allins.PPC_scv

PPC_rfscv = _ida_allins.PPC_rfscv

PPC_stop = _ida_allins.PPC_stop

PPC_copy = _ida_allins.PPC_copy

PPC_paste = _ida_allins.PPC_paste

PPC_ldat = _ida_allins.PPC_ldat

PPC_lwat = _ida_allins.PPC_lwat

PPC_stdat = _ida_allins.PPC_stdat

PPC_stwat = _ida_allins.PPC_stwat

PPC_cpabort = _ida_allins.PPC_cpabort

PPC_wait30 = _ida_allins.PPC_wait30

PPC_dtstsfi = _ida_allins.PPC_dtstsfi

PPC_dtstsfiq = _ida_allins.PPC_dtstsfiq

PPC_bcdcfn = _ida_allins.PPC_bcdcfn

PPC_bcdcfz = _ida_allins.PPC_bcdcfz

PPC_bcdctn = _ida_allins.PPC_bcdctn

PPC_bcdctz = _ida_allins.PPC_bcdctz

PPC_bcdctsq = _ida_allins.PPC_bcdctsq

PPC_bcdcfsq = _ida_allins.PPC_bcdcfsq

PPC_bcdsetsgn = _ida_allins.PPC_bcdsetsgn

PPC_bcdcpsgn = _ida_allins.PPC_bcdcpsgn

PPC_bcds = _ida_allins.PPC_bcds

PPC_bcdus = _ida_allins.PPC_bcdus

PPC_bcdsr = _ida_allins.PPC_bcdsr

PPC_bcdtrunc = _ida_allins.PPC_bcdtrunc

PPC_bcdutrunc = _ida_allins.PPC_bcdutrunc

PPC_vabsdub = _ida_allins.PPC_vabsdub

PPC_vabsduh = _ida_allins.PPC_vabsduh

PPC_vabsduw = _ida_allins.PPC_vabsduw

PPC_vbpermd = _ida_allins.PPC_vbpermd

PPC_vclzlsbb = _ida_allins.PPC_vclzlsbb

PPC_vctzlsbb = _ida_allins.PPC_vctzlsbb

PPC_vcmpneb = _ida_allins.PPC_vcmpneb

PPC_vcmpnezb = _ida_allins.PPC_vcmpnezb

PPC_vcmpneh = _ida_allins.PPC_vcmpneh

PPC_vcmpnezh = _ida_allins.PPC_vcmpnezh

PPC_vcmpnew = _ida_allins.PPC_vcmpnew

PPC_vcmpnezw = _ida_allins.PPC_vcmpnezw

PPC_vctzb = _ida_allins.PPC_vctzb

PPC_vctzh = _ida_allins.PPC_vctzh

PPC_vctzw = _ida_allins.PPC_vctzw

PPC_vctzd = _ida_allins.PPC_vctzd

PPC_vextractub = _ida_allins.PPC_vextractub

PPC_vextractuh = _ida_allins.PPC_vextractuh

PPC_vextractuw = _ida_allins.PPC_vextractuw

PPC_vextractd = _ida_allins.PPC_vextractd

PPC_vextsb2w = _ida_allins.PPC_vextsb2w

PPC_vextsb2d = _ida_allins.PPC_vextsb2d

PPC_vextsh2w = _ida_allins.PPC_vextsh2w

PPC_vextsh2d = _ida_allins.PPC_vextsh2d

PPC_vextsw2d = _ida_allins.PPC_vextsw2d

PPC_vextublx = _ida_allins.PPC_vextublx

PPC_vextubrx = _ida_allins.PPC_vextubrx

PPC_vextuhlx = _ida_allins.PPC_vextuhlx

PPC_vextuhrx = _ida_allins.PPC_vextuhrx

PPC_vextuwlx = _ida_allins.PPC_vextuwlx

PPC_vextuwrx = _ida_allins.PPC_vextuwrx

PPC_vinsertb = _ida_allins.PPC_vinsertb

PPC_vinserth = _ida_allins.PPC_vinserth

PPC_vinsertw = _ida_allins.PPC_vinsertw

PPC_vinsertd = _ida_allins.PPC_vinsertd

PPC_vmul10uq = _ida_allins.PPC_vmul10uq

PPC_vmul10euq = _ida_allins.PPC_vmul10euq

PPC_vmul10cuq = _ida_allins.PPC_vmul10cuq

PPC_vmul10ecuq = _ida_allins.PPC_vmul10ecuq

PPC_vnegw = _ida_allins.PPC_vnegw

PPC_vnegd = _ida_allins.PPC_vnegd

PPC_vpermr = _ida_allins.PPC_vpermr

PPC_vprtybw = _ida_allins.PPC_vprtybw

PPC_vprtybd = _ida_allins.PPC_vprtybd

PPC_vprtybq = _ida_allins.PPC_vprtybq

PPC_vrlwnm = _ida_allins.PPC_vrlwnm

PPC_vrlwmi = _ida_allins.PPC_vrlwmi

PPC_vrldnm = _ida_allins.PPC_vrldnm

PPC_vrldmi = _ida_allins.PPC_vrldmi

PPC_vslv = _ida_allins.PPC_vslv

PPC_vsrv = _ida_allins.PPC_vsrv

PPC_lxsd = _ida_allins.PPC_lxsd

PPC_lxssp = _ida_allins.PPC_lxssp

PPC_lxsibzx = _ida_allins.PPC_lxsibzx

PPC_lxsihzx = _ida_allins.PPC_lxsihzx

PPC_lxv = _ida_allins.PPC_lxv

PPC_lxvb16x = _ida_allins.PPC_lxvb16x

PPC_lxvh8x = _ida_allins.PPC_lxvh8x

PPC_lxvl = _ida_allins.PPC_lxvl

PPC_lxvll = _ida_allins.PPC_lxvll

PPC_lxvwsx = _ida_allins.PPC_lxvwsx

PPC_lxvx = _ida_allins.PPC_lxvx

PPC_stxsd = _ida_allins.PPC_stxsd

PPC_stxsibx = _ida_allins.PPC_stxsibx

PPC_stxsihx = _ida_allins.PPC_stxsihx

PPC_stxssp = _ida_allins.PPC_stxssp

PPC_stxv = _ida_allins.PPC_stxv

PPC_stxvb16x = _ida_allins.PPC_stxvb16x

PPC_stxvh8x = _ida_allins.PPC_stxvh8x

PPC_stxvl = _ida_allins.PPC_stxvl

PPC_stxvll = _ida_allins.PPC_stxvll

PPC_stxvx = _ida_allins.PPC_stxvx

PPC_xsabsqp = _ida_allins.PPC_xsabsqp

PPC_xsaddqp = _ida_allins.PPC_xsaddqp

PPC_xscmpexpqp = _ida_allins.PPC_xscmpexpqp

PPC_xscmpoqp = _ida_allins.PPC_xscmpoqp

PPC_xscmpuqp = _ida_allins.PPC_xscmpuqp

PPC_xscpsgnqp = _ida_allins.PPC_xscpsgnqp

PPC_xscvdpqp = _ida_allins.PPC_xscvdpqp

PPC_xscvqpdp = _ida_allins.PPC_xscvqpdp

PPC_xscvqpsdz = _ida_allins.PPC_xscvqpsdz

PPC_xscvqpswz = _ida_allins.PPC_xscvqpswz

PPC_xscvqpudz = _ida_allins.PPC_xscvqpudz

PPC_xscvqpuwz = _ida_allins.PPC_xscvqpuwz

PPC_xscvsdqp = _ida_allins.PPC_xscvsdqp

PPC_xscvudqp = _ida_allins.PPC_xscvudqp

PPC_xsdivqp = _ida_allins.PPC_xsdivqp

PPC_xsiexpqp = _ida_allins.PPC_xsiexpqp

PPC_xsmaddqp = _ida_allins.PPC_xsmaddqp

PPC_xsmsubqp = _ida_allins.PPC_xsmsubqp

PPC_xsmulqp = _ida_allins.PPC_xsmulqp

PPC_xsnabsqp = _ida_allins.PPC_xsnabsqp

PPC_xsnegqp = _ida_allins.PPC_xsnegqp

PPC_xsnmaddqp = _ida_allins.PPC_xsnmaddqp

PPC_xsnmsubqp = _ida_allins.PPC_xsnmsubqp

PPC_xssqrtqp = _ida_allins.PPC_xssqrtqp

PPC_xssubqp = _ida_allins.PPC_xssubqp

PPC_xsxexpqp = _ida_allins.PPC_xsxexpqp

PPC_xsxsigqp = _ida_allins.PPC_xsxsigqp

PPC_xststdcqp = _ida_allins.PPC_xststdcqp

PPC_xsrqpxp = _ida_allins.PPC_xsrqpxp

PPC_xsrqpi = _ida_allins.PPC_xsrqpi

PPC_xscmpeqdp = _ida_allins.PPC_xscmpeqdp

PPC_xscmpexpdp = _ida_allins.PPC_xscmpexpdp

PPC_xscmpgedp = _ida_allins.PPC_xscmpgedp

PPC_xscmpgtdp = _ida_allins.PPC_xscmpgtdp

PPC_xsiexpdp = _ida_allins.PPC_xsiexpdp

PPC_xsmaxcdp = _ida_allins.PPC_xsmaxcdp

PPC_xsmaxjdp = _ida_allins.PPC_xsmaxjdp

PPC_xsmincdp = _ida_allins.PPC_xsmincdp

PPC_xsminjdp = _ida_allins.PPC_xsminjdp

PPC_xviexpdp = _ida_allins.PPC_xviexpdp

PPC_xviexpsp = _ida_allins.PPC_xviexpsp

PPC_xxextractuw = _ida_allins.PPC_xxextractuw

PPC_xxinsertw = _ida_allins.PPC_xxinsertw

PPC_xxperm = _ida_allins.PPC_xxperm

PPC_xxpermr = _ida_allins.PPC_xxpermr

PPC_xxspltib = _ida_allins.PPC_xxspltib

PPC_xststdcdp = _ida_allins.PPC_xststdcdp

PPC_xststdcsp = _ida_allins.PPC_xststdcsp

PPC_xvtstdcdp = _ida_allins.PPC_xvtstdcdp

PPC_xvtstdcsp = _ida_allins.PPC_xvtstdcsp

PPC_xsxexpdp = _ida_allins.PPC_xsxexpdp

PPC_xsxsigdp = _ida_allins.PPC_xsxsigdp

PPC_xscvdphp = _ida_allins.PPC_xscvdphp

PPC_xscvhpdp = _ida_allins.PPC_xscvhpdp

PPC_xvxexpdp = _ida_allins.PPC_xvxexpdp

PPC_xvxexpsp = _ida_allins.PPC_xvxexpsp

PPC_xvxsigdp = _ida_allins.PPC_xvxsigdp

PPC_xvxsigsp = _ida_allins.PPC_xvxsigsp

PPC_xxbrd = _ida_allins.PPC_xxbrd

PPC_xxbrh = _ida_allins.PPC_xxbrh

PPC_xxbrq = _ida_allins.PPC_xxbrq

PPC_xxbrw = _ida_allins.PPC_xxbrw

PPC_xvcvhpsp = _ida_allins.PPC_xvcvhpsp

PPC_xvcvsphp = _ida_allins.PPC_xvcvsphp

PPC_msgsync = _ida_allins.PPC_msgsync

PPC_addex = _ida_allins.PPC_addex

PPC_vmsumudm = _ida_allins.PPC_vmsumudm

PPC_mffsce = _ida_allins.PPC_mffsce

PPC_mffscdrn = _ida_allins.PPC_mffscdrn

PPC_mffscdrni = _ida_allins.PPC_mffscdrni

PPC_mffscrn = _ida_allins.PPC_mffscrn

PPC_mffscrni = _ida_allins.PPC_mffscrni

PPC_mffsl = _ida_allins.PPC_mffsl

PPC_lbdcbx = _ida_allins.PPC_lbdcbx

PPC_lhdcbx = _ida_allins.PPC_lhdcbx

PPC_lwdcbx = _ida_allins.PPC_lwdcbx

PPC_stbdcbx = _ida_allins.PPC_stbdcbx

PPC_sthdcbx = _ida_allins.PPC_sthdcbx

PPC_stwdcbx = _ida_allins.PPC_stwdcbx

PPC_lbcbx = _ida_allins.PPC_lbcbx

PPC_lhcbx = _ida_allins.PPC_lhcbx

PPC_lwcbx = _ida_allins.PPC_lwcbx

PPC_stbwtx = _ida_allins.PPC_stbwtx

PPC_sthwtx = _ida_allins.PPC_sthwtx

PPC_stwwtx = _ida_allins.PPC_stwwtx

PPC_dsncb = _ida_allins.PPC_dsncb

PPC_ldw = _ida_allins.PPC_ldw

PPC_stdw = _ida_allins.PPC_stdw

PPC_lqw = _ida_allins.PPC_lqw

PPC_stqw = _ida_allins.PPC_stqw

PPC_ldwcb = _ida_allins.PPC_ldwcb

PPC_ldbrw = _ida_allins.PPC_ldbrw

PPC_ldwbrw = _ida_allins.PPC_ldwbrw

PPC_stdwwt = _ida_allins.PPC_stdwwt

PPC_stdbrw = _ida_allins.PPC_stdbrw

PPC_stdwbrw = _ida_allins.PPC_stdwbrw

PPC_lqdbrw = _ida_allins.PPC_lqdbrw

PPC_stqdbrw = _ida_allins.PPC_stqdbrw

PPC_lwbr = _ida_allins.PPC_lwbr

PPC_lhbr = _ida_allins.PPC_lhbr

PPC_stwbr = _ida_allins.PPC_stwbr

PPC_sthbr = _ida_allins.PPC_sthbr

PPC_ldwar = _ida_allins.PPC_ldwar

PPC_stdwc = _ida_allins.PPC_stdwc

PPC_addb = _ida_allins.PPC_addb

PPC_addbu = _ida_allins.PPC_addbu

PPC_addh = _ida_allins.PPC_addh

PPC_addhu = _ida_allins.PPC_addhu

PPC_subfb = _ida_allins.PPC_subfb

PPC_subfbu = _ida_allins.PPC_subfbu

PPC_subfh = _ida_allins.PPC_subfh

PPC_subfhu = _ida_allins.PPC_subfhu

PPC_byterevw = _ida_allins.PPC_byterevw

PPC_byterevh = _ida_allins.PPC_byterevh

PPC_hwaccel = _ida_allins.PPC_hwaccel

PPC_hwacceli = _ida_allins.PPC_hwacceli

PPC_ordhwaccel = _ida_allins.PPC_ordhwaccel

PPC_ordhwacceli = _ida_allins.PPC_ordhwacceli

PPC_osmcmd = _ida_allins.PPC_osmcmd

PPC_mpure = _ida_allins.PPC_mpure

PPC_mpuwe = _ida_allins.PPC_mpuwe

PPC_mpusync = _ida_allins.PPC_mpusync

PPC_efdmax = _ida_allins.PPC_efdmax

PPC_efdmin = _ida_allins.PPC_efdmin

PPC_efdsqrt = _ida_allins.PPC_efdsqrt

PPC_efdcfh = _ida_allins.PPC_efdcfh

PPC_efdcth = _ida_allins.PPC_efdcth

PPC_last = _ida_allins.PPC_last

NEC850_NULL = _ida_allins.NEC850_NULL

NEC850_BREAKPOINT = _ida_allins.NEC850_BREAKPOINT

NEC850_XORI = _ida_allins.NEC850_XORI

NEC850_XOR = _ida_allins.NEC850_XOR

NEC850_TST1 = _ida_allins.NEC850_TST1

NEC850_TST = _ida_allins.NEC850_TST

NEC850_TRAP = _ida_allins.NEC850_TRAP

NEC850_SUBR = _ida_allins.NEC850_SUBR

NEC850_SUB = _ida_allins.NEC850_SUB

NEC850_STSR = _ida_allins.NEC850_STSR

NEC850_ST_B = _ida_allins.NEC850_ST_B

NEC850_ST_H = _ida_allins.NEC850_ST_H

NEC850_ST_W = _ida_allins.NEC850_ST_W

NEC850_SST_B = _ida_allins.NEC850_SST_B

NEC850_SST_H = _ida_allins.NEC850_SST_H

NEC850_SST_W = _ida_allins.NEC850_SST_W

NEC850_SLD_B = _ida_allins.NEC850_SLD_B

NEC850_SLD_H = _ida_allins.NEC850_SLD_H

NEC850_SLD_W = _ida_allins.NEC850_SLD_W

NEC850_SHR = _ida_allins.NEC850_SHR

NEC850_SHL = _ida_allins.NEC850_SHL

NEC850_SET1 = _ida_allins.NEC850_SET1

NEC850_SETF = _ida_allins.NEC850_SETF

NEC850_SATSUBR = _ida_allins.NEC850_SATSUBR

NEC850_SATSUBI = _ida_allins.NEC850_SATSUBI

NEC850_SATSUB = _ida_allins.NEC850_SATSUB

NEC850_SATADD = _ida_allins.NEC850_SATADD

NEC850_SAR = _ida_allins.NEC850_SAR

NEC850_RETI = _ida_allins.NEC850_RETI

NEC850_ORI = _ida_allins.NEC850_ORI

NEC850_OR = _ida_allins.NEC850_OR

NEC850_NOT1 = _ida_allins.NEC850_NOT1

NEC850_NOT = _ida_allins.NEC850_NOT

NEC850_NOP = _ida_allins.NEC850_NOP

NEC850_MULHI = _ida_allins.NEC850_MULHI

NEC850_MULH = _ida_allins.NEC850_MULH

NEC850_MOVHI = _ida_allins.NEC850_MOVHI

NEC850_MOVEA = _ida_allins.NEC850_MOVEA

NEC850_MOV = _ida_allins.NEC850_MOV

NEC850_LDSR = _ida_allins.NEC850_LDSR

NEC850_LD_B = _ida_allins.NEC850_LD_B

NEC850_LD_H = _ida_allins.NEC850_LD_H

NEC850_LD_W = _ida_allins.NEC850_LD_W

NEC850_JR = _ida_allins.NEC850_JR

NEC850_JMP = _ida_allins.NEC850_JMP

NEC850_JARL = _ida_allins.NEC850_JARL

NEC850_HALT = _ida_allins.NEC850_HALT

NEC850_EI = _ida_allins.NEC850_EI

NEC850_DIVH = _ida_allins.NEC850_DIVH

NEC850_DI = _ida_allins.NEC850_DI

NEC850_CMP = _ida_allins.NEC850_CMP

NEC850_CLR1 = _ida_allins.NEC850_CLR1

NEC850_BV = _ida_allins.NEC850_BV

NEC850_BL = _ida_allins.NEC850_BL

NEC850_BZ = _ida_allins.NEC850_BZ

NEC850_BNH = _ida_allins.NEC850_BNH

NEC850_BN = _ida_allins.NEC850_BN

NEC850_BR = _ida_allins.NEC850_BR

NEC850_BLT = _ida_allins.NEC850_BLT

NEC850_BLE = _ida_allins.NEC850_BLE

NEC850_BNV = _ida_allins.NEC850_BNV

NEC850_BNC = _ida_allins.NEC850_BNC

NEC850_BNZ = _ida_allins.NEC850_BNZ

NEC850_BH = _ida_allins.NEC850_BH

NEC850_BP = _ida_allins.NEC850_BP

NEC850_BSA = _ida_allins.NEC850_BSA

NEC850_BGE = _ida_allins.NEC850_BGE

NEC850_BGT = _ida_allins.NEC850_BGT

NEC850_ANDI = _ida_allins.NEC850_ANDI

NEC850_AND = _ida_allins.NEC850_AND

NEC850_ADDI = _ida_allins.NEC850_ADDI

NEC850_ADD = _ida_allins.NEC850_ADD

NEC850_SWITCH = _ida_allins.NEC850_SWITCH

NEC850_ZXB = _ida_allins.NEC850_ZXB

NEC850_SXB = _ida_allins.NEC850_SXB

NEC850_ZXH = _ida_allins.NEC850_ZXH

NEC850_SXH = _ida_allins.NEC850_SXH

NEC850_DISPOSE_r0 = _ida_allins.NEC850_DISPOSE_r0

NEC850_DISPOSE_r = _ida_allins.NEC850_DISPOSE_r

NEC850_CALLT = _ida_allins.NEC850_CALLT

NEC850_DBTRAP = _ida_allins.NEC850_DBTRAP

NEC850_DBRET = _ida_allins.NEC850_DBRET

NEC850_CTRET = _ida_allins.NEC850_CTRET

NEC850_SASF = _ida_allins.NEC850_SASF

NEC850_PREPARE_sp = _ida_allins.NEC850_PREPARE_sp

NEC850_PREPARE_i = _ida_allins.NEC850_PREPARE_i

NEC850_MUL = _ida_allins.NEC850_MUL

NEC850_MULU = _ida_allins.NEC850_MULU

NEC850_DIVH_r3 = _ida_allins.NEC850_DIVH_r3

NEC850_DIVHU = _ida_allins.NEC850_DIVHU

NEC850_DIV = _ida_allins.NEC850_DIV

NEC850_DIVU = _ida_allins.NEC850_DIVU

NEC850_BSW = _ida_allins.NEC850_BSW

NEC850_BSH = _ida_allins.NEC850_BSH

NEC850_HSW = _ida_allins.NEC850_HSW

NEC850_CMOV = _ida_allins.NEC850_CMOV

NEC850_SLD_BU = _ida_allins.NEC850_SLD_BU

NEC850_SLD_HU = _ida_allins.NEC850_SLD_HU

NEC850_LD_BU = _ida_allins.NEC850_LD_BU

NEC850_LD_HU = _ida_allins.NEC850_LD_HU

NEC850_ADF = _ida_allins.NEC850_ADF

NEC850_HSH = _ida_allins.NEC850_HSH

NEC850_MAC = _ida_allins.NEC850_MAC

NEC850_MACU = _ida_allins.NEC850_MACU

NEC850_SBF = _ida_allins.NEC850_SBF

NEC850_SCH0L = _ida_allins.NEC850_SCH0L

NEC850_SCH0R = _ida_allins.NEC850_SCH0R

NEC850_SCH1L = _ida_allins.NEC850_SCH1L

NEC850_SCH1R = _ida_allins.NEC850_SCH1R

NEC850_CAXI = _ida_allins.NEC850_CAXI

NEC850_DIVQ = _ida_allins.NEC850_DIVQ

NEC850_DIVQU = _ida_allins.NEC850_DIVQU

NEC850_EIRET = _ida_allins.NEC850_EIRET

NEC850_FERET = _ida_allins.NEC850_FERET

NEC850_FETRAP = _ida_allins.NEC850_FETRAP

NEC850_RMTRAP = _ida_allins.NEC850_RMTRAP

NEC850_RIE = _ida_allins.NEC850_RIE

NEC850_SYNCE = _ida_allins.NEC850_SYNCE

NEC850_SYNCM = _ida_allins.NEC850_SYNCM

NEC850_SYNCP = _ida_allins.NEC850_SYNCP

NEC850_SYSCALL = _ida_allins.NEC850_SYSCALL

NEC850_CVT_SW = _ida_allins.NEC850_CVT_SW

NEC850_TRNC_SW = _ida_allins.NEC850_TRNC_SW

NEC850_CVT_WS = _ida_allins.NEC850_CVT_WS

NEC850_LDFC = _ida_allins.NEC850_LDFC

NEC850_LDFF = _ida_allins.NEC850_LDFF

NEC850_STFC = _ida_allins.NEC850_STFC

NEC850_STFF = _ida_allins.NEC850_STFF

NEC850_TRFF = _ida_allins.NEC850_TRFF

NEC850_ABSF_D = _ida_allins.NEC850_ABSF_D

NEC850_ABSF_S = _ida_allins.NEC850_ABSF_S

NEC850_ADDF_D = _ida_allins.NEC850_ADDF_D

NEC850_ADDF_S = _ida_allins.NEC850_ADDF_S

NEC850_DIVF_D = _ida_allins.NEC850_DIVF_D

NEC850_DIVF_S = _ida_allins.NEC850_DIVF_S

NEC850_MAXF_D = _ida_allins.NEC850_MAXF_D

NEC850_MAXF_S = _ida_allins.NEC850_MAXF_S

NEC850_MINF_D = _ida_allins.NEC850_MINF_D

NEC850_MINF_S = _ida_allins.NEC850_MINF_S

NEC850_MULF_D = _ida_allins.NEC850_MULF_D

NEC850_MULF_S = _ida_allins.NEC850_MULF_S

NEC850_NEGF_D = _ida_allins.NEC850_NEGF_D

NEC850_NEGF_S = _ida_allins.NEC850_NEGF_S

NEC850_RECIPF_D = _ida_allins.NEC850_RECIPF_D

NEC850_RECIPF_S = _ida_allins.NEC850_RECIPF_S

NEC850_RSQRTF_D = _ida_allins.NEC850_RSQRTF_D

NEC850_RSQRTF_S = _ida_allins.NEC850_RSQRTF_S

NEC850_SQRTF_D = _ida_allins.NEC850_SQRTF_D

NEC850_SQRTF_S = _ida_allins.NEC850_SQRTF_S

NEC850_SUBF_D = _ida_allins.NEC850_SUBF_D

NEC850_SUBF_S = _ida_allins.NEC850_SUBF_S

NEC850_MADDF_S = _ida_allins.NEC850_MADDF_S

NEC850_MSUBF_S = _ida_allins.NEC850_MSUBF_S

NEC850_NMADDF_S = _ida_allins.NEC850_NMADDF_S

NEC850_NMSUBF_S = _ida_allins.NEC850_NMSUBF_S

NEC850_CEILF_DL = _ida_allins.NEC850_CEILF_DL

NEC850_CEILF_DW = _ida_allins.NEC850_CEILF_DW

NEC850_CEILF_SL = _ida_allins.NEC850_CEILF_SL

NEC850_CEILF_SW = _ida_allins.NEC850_CEILF_SW

NEC850_CEILF_DUL = _ida_allins.NEC850_CEILF_DUL

NEC850_CEILF_DUW = _ida_allins.NEC850_CEILF_DUW

NEC850_CEILF_SUL = _ida_allins.NEC850_CEILF_SUL

NEC850_CEILF_SUW = _ida_allins.NEC850_CEILF_SUW

NEC850_CVTF_DL = _ida_allins.NEC850_CVTF_DL

NEC850_CVTF_DS = _ida_allins.NEC850_CVTF_DS

NEC850_CVTF_DUL = _ida_allins.NEC850_CVTF_DUL

NEC850_CVTF_DUW = _ida_allins.NEC850_CVTF_DUW

NEC850_CVTF_DW = _ida_allins.NEC850_CVTF_DW

NEC850_CVTF_LD = _ida_allins.NEC850_CVTF_LD

NEC850_CVTF_LS = _ida_allins.NEC850_CVTF_LS

NEC850_CVTF_SD = _ida_allins.NEC850_CVTF_SD

NEC850_CVTF_SL = _ida_allins.NEC850_CVTF_SL

NEC850_CVTF_SUL = _ida_allins.NEC850_CVTF_SUL

NEC850_CVTF_SUW = _ida_allins.NEC850_CVTF_SUW

NEC850_CVTF_SW = _ida_allins.NEC850_CVTF_SW

NEC850_CVTF_ULD = _ida_allins.NEC850_CVTF_ULD

NEC850_CVTF_ULS = _ida_allins.NEC850_CVTF_ULS

NEC850_CVTF_UWD = _ida_allins.NEC850_CVTF_UWD

NEC850_CVTF_UWS = _ida_allins.NEC850_CVTF_UWS

NEC850_CVTF_WD = _ida_allins.NEC850_CVTF_WD

NEC850_CVTF_WS = _ida_allins.NEC850_CVTF_WS

NEC850_FLOORF_DL = _ida_allins.NEC850_FLOORF_DL

NEC850_FLOORF_DW = _ida_allins.NEC850_FLOORF_DW

NEC850_FLOORF_SL = _ida_allins.NEC850_FLOORF_SL

NEC850_FLOORF_SW = _ida_allins.NEC850_FLOORF_SW

NEC850_FLOORF_DUL = _ida_allins.NEC850_FLOORF_DUL

NEC850_FLOORF_DUW = _ida_allins.NEC850_FLOORF_DUW

NEC850_FLOORF_SUL = _ida_allins.NEC850_FLOORF_SUL

NEC850_FLOORF_SUW = _ida_allins.NEC850_FLOORF_SUW

NEC850_TRNCF_DL = _ida_allins.NEC850_TRNCF_DL

NEC850_TRNCF_DUL = _ida_allins.NEC850_TRNCF_DUL

NEC850_TRNCF_DUW = _ida_allins.NEC850_TRNCF_DUW

NEC850_TRNCF_DW = _ida_allins.NEC850_TRNCF_DW

NEC850_TRNCF_SL = _ida_allins.NEC850_TRNCF_SL

NEC850_TRNCF_SUL = _ida_allins.NEC850_TRNCF_SUL

NEC850_TRNCF_SUW = _ida_allins.NEC850_TRNCF_SUW

NEC850_TRNCF_SW = _ida_allins.NEC850_TRNCF_SW

NEC850_CMPF_S = _ida_allins.NEC850_CMPF_S

NEC850_CMPF_D = _ida_allins.NEC850_CMPF_D

NEC850_CMOVF_S = _ida_allins.NEC850_CMOVF_S

NEC850_CMOVF_D = _ida_allins.NEC850_CMOVF_D

NEC850_TRFSR = _ida_allins.NEC850_TRFSR

NEC850_SYNCI = _ida_allins.NEC850_SYNCI

NEC850_SNOOZE = _ida_allins.NEC850_SNOOZE

NEC850_BINS = _ida_allins.NEC850_BINS

NEC850_ROTL = _ida_allins.NEC850_ROTL

NEC850_LOOP = _ida_allins.NEC850_LOOP

NEC850_LD_DW = _ida_allins.NEC850_LD_DW

NEC850_ST_DW = _ida_allins.NEC850_ST_DW

NEC850_LDL_W = _ida_allins.NEC850_LDL_W

NEC850_STC_W = _ida_allins.NEC850_STC_W

NEC850_CLL = _ida_allins.NEC850_CLL

NEC850_CACHE = _ida_allins.NEC850_CACHE

NEC850_PREF = _ida_allins.NEC850_PREF

NEC850_PUSHSP = _ida_allins.NEC850_PUSHSP

NEC850_POPSP = _ida_allins.NEC850_POPSP

NEC850_CVTF_HS = _ida_allins.NEC850_CVTF_HS

NEC850_CVTF_SH = _ida_allins.NEC850_CVTF_SH

NEC850_FMAF_S = _ida_allins.NEC850_FMAF_S

NEC850_FMSF_S = _ida_allins.NEC850_FMSF_S

NEC850_FNMAF_S = _ida_allins.NEC850_FNMAF_S

NEC850_FNMSF_S = _ida_allins.NEC850_FNMSF_S

NEC850_DBPUSH = _ida_allins.NEC850_DBPUSH

NEC850_DBCP = _ida_allins.NEC850_DBCP

NEC850_DBTAG = _ida_allins.NEC850_DBTAG

NEC850_DBHVTRAP = _ida_allins.NEC850_DBHVTRAP

NEC850_EST = _ida_allins.NEC850_EST

NEC850_DST = _ida_allins.NEC850_DST

NEC850_HVTRAP = _ida_allins.NEC850_HVTRAP

NEC850_HVCALL = _ida_allins.NEC850_HVCALL

NEC850_LDVC_SR = _ida_allins.NEC850_LDVC_SR

NEC850_STVC_SR = _ida_allins.NEC850_STVC_SR

NEC850_LDTC_GR = _ida_allins.NEC850_LDTC_GR

NEC850_STTC_GR = _ida_allins.NEC850_STTC_GR

NEC850_LDTC_PC = _ida_allins.NEC850_LDTC_PC

NEC850_STTC_PC = _ida_allins.NEC850_STTC_PC

NEC850_LDTC_SR = _ida_allins.NEC850_LDTC_SR

NEC850_STTC_SR = _ida_allins.NEC850_STTC_SR

NEC850_LDTC_VR = _ida_allins.NEC850_LDTC_VR

NEC850_STTC_VR = _ida_allins.NEC850_STTC_VR

NEC850_TLBAI = _ida_allins.NEC850_TLBAI

NEC850_TLBR = _ida_allins.NEC850_TLBR

NEC850_TLBS = _ida_allins.NEC850_TLBS

NEC850_TLBVI = _ida_allins.NEC850_TLBVI

NEC850_TLBW = _ida_allins.NEC850_TLBW

NEC850_LAST_INSTRUCTION = _ida_allins.NEC850_LAST_INSTRUCTION

TRICORE_null = _ida_allins.TRICORE_null

TRICORE_abs = _ida_allins.TRICORE_abs

TRICORE_abs_b = _ida_allins.TRICORE_abs_b

TRICORE_abs_h = _ida_allins.TRICORE_abs_h

TRICORE_absdif = _ida_allins.TRICORE_absdif

TRICORE_absdif_b = _ida_allins.TRICORE_absdif_b

TRICORE_absdif_h = _ida_allins.TRICORE_absdif_h

TRICORE_absdifs = _ida_allins.TRICORE_absdifs

TRICORE_absdifs_h = _ida_allins.TRICORE_absdifs_h

TRICORE_abss = _ida_allins.TRICORE_abss

TRICORE_abss_h = _ida_allins.TRICORE_abss_h

TRICORE_add_b = _ida_allins.TRICORE_add_b

TRICORE_add_f = _ida_allins.TRICORE_add_f

TRICORE_add_h = _ida_allins.TRICORE_add_h

TRICORE_add16 = _ida_allins.TRICORE_add16

TRICORE_add16_a = _ida_allins.TRICORE_add16_a

TRICORE_add32 = _ida_allins.TRICORE_add32

TRICORE_add32_a = _ida_allins.TRICORE_add32_a

TRICORE_addc = _ida_allins.TRICORE_addc

TRICORE_addi = _ida_allins.TRICORE_addi

TRICORE_addih = _ida_allins.TRICORE_addih

TRICORE_addih_a = _ida_allins.TRICORE_addih_a

TRICORE_adds = _ida_allins.TRICORE_adds

TRICORE_adds_h = _ida_allins.TRICORE_adds_h

TRICORE_adds_hu = _ida_allins.TRICORE_adds_hu

TRICORE_adds_u = _ida_allins.TRICORE_adds_u

TRICORE_adds16 = _ida_allins.TRICORE_adds16

TRICORE_addsc_at = _ida_allins.TRICORE_addsc_at

TRICORE_addsc16_a = _ida_allins.TRICORE_addsc16_a

TRICORE_addsc32_a = _ida_allins.TRICORE_addsc32_a

TRICORE_addx = _ida_allins.TRICORE_addx

TRICORE_and_and_t = _ida_allins.TRICORE_and_and_t

TRICORE_and_andn_t = _ida_allins.TRICORE_and_andn_t

TRICORE_and_eq = _ida_allins.TRICORE_and_eq

TRICORE_and_ge = _ida_allins.TRICORE_and_ge

TRICORE_and_ge_u = _ida_allins.TRICORE_and_ge_u

TRICORE_and_lt = _ida_allins.TRICORE_and_lt

TRICORE_and_lt_u = _ida_allins.TRICORE_and_lt_u

TRICORE_and_ne = _ida_allins.TRICORE_and_ne

TRICORE_and_nor_t = _ida_allins.TRICORE_and_nor_t

TRICORE_and_or_t = _ida_allins.TRICORE_and_or_t

TRICORE_and_t = _ida_allins.TRICORE_and_t

TRICORE_and16 = _ida_allins.TRICORE_and16

TRICORE_and32 = _ida_allins.TRICORE_and32

TRICORE_andn = _ida_allins.TRICORE_andn

TRICORE_andn_t = _ida_allins.TRICORE_andn_t

TRICORE_bisr16 = _ida_allins.TRICORE_bisr16

TRICORE_bisr32 = _ida_allins.TRICORE_bisr32

TRICORE_bmerge = _ida_allins.TRICORE_bmerge

TRICORE_bsplit = _ida_allins.TRICORE_bsplit

TRICORE_cachea_i = _ida_allins.TRICORE_cachea_i

TRICORE_cachea_w = _ida_allins.TRICORE_cachea_w

TRICORE_cachea_wi = _ida_allins.TRICORE_cachea_wi

TRICORE_cadd16 = _ida_allins.TRICORE_cadd16

TRICORE_cadd32 = _ida_allins.TRICORE_cadd32

TRICORE_caddn16 = _ida_allins.TRICORE_caddn16

TRICORE_caddn32 = _ida_allins.TRICORE_caddn32

TRICORE_call16 = _ida_allins.TRICORE_call16

TRICORE_call32 = _ida_allins.TRICORE_call32

TRICORE_calla = _ida_allins.TRICORE_calla

TRICORE_calli = _ida_allins.TRICORE_calli

TRICORE_clo = _ida_allins.TRICORE_clo

TRICORE_clo_h = _ida_allins.TRICORE_clo_h

TRICORE_cls = _ida_allins.TRICORE_cls

TRICORE_cls_h = _ida_allins.TRICORE_cls_h

TRICORE_clz = _ida_allins.TRICORE_clz

TRICORE_clz_h = _ida_allins.TRICORE_clz_h

TRICORE_cmov16 = _ida_allins.TRICORE_cmov16

TRICORE_cmovn16 = _ida_allins.TRICORE_cmovn16

TRICORE_cmp_f = _ida_allins.TRICORE_cmp_f

TRICORE_csub = _ida_allins.TRICORE_csub

TRICORE_csubn = _ida_allins.TRICORE_csubn

TRICORE_debug16 = _ida_allins.TRICORE_debug16

TRICORE_debug32 = _ida_allins.TRICORE_debug32

TRICORE_dextr = _ida_allins.TRICORE_dextr

TRICORE_disable = _ida_allins.TRICORE_disable

TRICORE_div_f = _ida_allins.TRICORE_div_f

TRICORE_dsync = _ida_allins.TRICORE_dsync

TRICORE_dvadj = _ida_allins.TRICORE_dvadj

TRICORE_dvinit = _ida_allins.TRICORE_dvinit

TRICORE_dvinit_b = _ida_allins.TRICORE_dvinit_b

TRICORE_dvinit_bu = _ida_allins.TRICORE_dvinit_bu

TRICORE_dvinit_h = _ida_allins.TRICORE_dvinit_h

TRICORE_dvinit_hu = _ida_allins.TRICORE_dvinit_hu

TRICORE_dvinit_u = _ida_allins.TRICORE_dvinit_u

TRICORE_dvstep = _ida_allins.TRICORE_dvstep

TRICORE_dvstep_u = _ida_allins.TRICORE_dvstep_u

TRICORE_enable = _ida_allins.TRICORE_enable

TRICORE_eq_a = _ida_allins.TRICORE_eq_a

TRICORE_eq_b = _ida_allins.TRICORE_eq_b

TRICORE_eq_h = _ida_allins.TRICORE_eq_h

TRICORE_eq_w = _ida_allins.TRICORE_eq_w

TRICORE_eq16 = _ida_allins.TRICORE_eq16

TRICORE_eq32 = _ida_allins.TRICORE_eq32

TRICORE_eqany_b = _ida_allins.TRICORE_eqany_b

TRICORE_eqany_h = _ida_allins.TRICORE_eqany_h

TRICORE_eqz_a = _ida_allins.TRICORE_eqz_a

TRICORE_extr = _ida_allins.TRICORE_extr

TRICORE_extr_u = _ida_allins.TRICORE_extr_u

TRICORE_ftoi = _ida_allins.TRICORE_ftoi

TRICORE_ftoq31 = _ida_allins.TRICORE_ftoq31

TRICORE_ftou = _ida_allins.TRICORE_ftou

TRICORE_ge = _ida_allins.TRICORE_ge

TRICORE_ge_a = _ida_allins.TRICORE_ge_a

TRICORE_ge_u = _ida_allins.TRICORE_ge_u

TRICORE_imask = _ida_allins.TRICORE_imask

TRICORE_ins_t = _ida_allins.TRICORE_ins_t

TRICORE_insert = _ida_allins.TRICORE_insert

TRICORE_insn_t = _ida_allins.TRICORE_insn_t

TRICORE_isync = _ida_allins.TRICORE_isync

TRICORE_itof = _ida_allins.TRICORE_itof

TRICORE_ixmax = _ida_allins.TRICORE_ixmax

TRICORE_ixmax_u = _ida_allins.TRICORE_ixmax_u

TRICORE_ixmin = _ida_allins.TRICORE_ixmin

TRICORE_ixmin_u = _ida_allins.TRICORE_ixmin_u

TRICORE_j16 = _ida_allins.TRICORE_j16

TRICORE_j32 = _ida_allins.TRICORE_j32

TRICORE_ja = _ida_allins.TRICORE_ja

TRICORE_jeq_a = _ida_allins.TRICORE_jeq_a

TRICORE_jeq16 = _ida_allins.TRICORE_jeq16

TRICORE_jeq32 = _ida_allins.TRICORE_jeq32

TRICORE_jge = _ida_allins.TRICORE_jge

TRICORE_jge_u = _ida_allins.TRICORE_jge_u

TRICORE_jgez16 = _ida_allins.TRICORE_jgez16

TRICORE_jgtz16 = _ida_allins.TRICORE_jgtz16

TRICORE_ji16 = _ida_allins.TRICORE_ji16

TRICORE_ji32 = _ida_allins.TRICORE_ji32

TRICORE_jl = _ida_allins.TRICORE_jl

TRICORE_jla = _ida_allins.TRICORE_jla

TRICORE_jlez16 = _ida_allins.TRICORE_jlez16

TRICORE_jli = _ida_allins.TRICORE_jli

TRICORE_jlt = _ida_allins.TRICORE_jlt

TRICORE_jlt_u = _ida_allins.TRICORE_jlt_u

TRICORE_jltz16 = _ida_allins.TRICORE_jltz16

TRICORE_jne_a = _ida_allins.TRICORE_jne_a

TRICORE_jne16 = _ida_allins.TRICORE_jne16

TRICORE_jne32 = _ida_allins.TRICORE_jne32

TRICORE_jned = _ida_allins.TRICORE_jned

TRICORE_jnei = _ida_allins.TRICORE_jnei

TRICORE_jnz16 = _ida_allins.TRICORE_jnz16

TRICORE_jnz16_a = _ida_allins.TRICORE_jnz16_a

TRICORE_jnz16_t = _ida_allins.TRICORE_jnz16_t

TRICORE_jnz32_a = _ida_allins.TRICORE_jnz32_a

TRICORE_jnz32_t = _ida_allins.TRICORE_jnz32_t

TRICORE_jz16 = _ida_allins.TRICORE_jz16

TRICORE_jz16_a = _ida_allins.TRICORE_jz16_a

TRICORE_jz16_t = _ida_allins.TRICORE_jz16_t

TRICORE_jz32_a = _ida_allins.TRICORE_jz32_a

TRICORE_jz32_t = _ida_allins.TRICORE_jz32_t

TRICORE_ld_b = _ida_allins.TRICORE_ld_b

TRICORE_ld_d = _ida_allins.TRICORE_ld_d

TRICORE_ld_da = _ida_allins.TRICORE_ld_da

TRICORE_ld_hu = _ida_allins.TRICORE_ld_hu

TRICORE_ld_q = _ida_allins.TRICORE_ld_q

TRICORE_ld16_a = _ida_allins.TRICORE_ld16_a

TRICORE_ld16_bu = _ida_allins.TRICORE_ld16_bu

TRICORE_ld16_h = _ida_allins.TRICORE_ld16_h

TRICORE_ld16_w = _ida_allins.TRICORE_ld16_w

TRICORE_ld32_a = _ida_allins.TRICORE_ld32_a

TRICORE_ld32_bu = _ida_allins.TRICORE_ld32_bu

TRICORE_ld32_h = _ida_allins.TRICORE_ld32_h

TRICORE_ld32_w = _ida_allins.TRICORE_ld32_w

TRICORE_ldlcx = _ida_allins.TRICORE_ldlcx

TRICORE_ldmst = _ida_allins.TRICORE_ldmst

TRICORE_lducx = _ida_allins.TRICORE_lducx

TRICORE_lea = _ida_allins.TRICORE_lea

TRICORE_loop16 = _ida_allins.TRICORE_loop16

TRICORE_loop32 = _ida_allins.TRICORE_loop32

TRICORE_loopu = _ida_allins.TRICORE_loopu

TRICORE_lt_a = _ida_allins.TRICORE_lt_a

TRICORE_lt_b = _ida_allins.TRICORE_lt_b

TRICORE_lt_bu = _ida_allins.TRICORE_lt_bu

TRICORE_lt_h = _ida_allins.TRICORE_lt_h

TRICORE_lt_hu = _ida_allins.TRICORE_lt_hu

TRICORE_lt_u = _ida_allins.TRICORE_lt_u

TRICORE_lt_w = _ida_allins.TRICORE_lt_w

TRICORE_lt_wu = _ida_allins.TRICORE_lt_wu

TRICORE_lt16 = _ida_allins.TRICORE_lt16

TRICORE_lt32 = _ida_allins.TRICORE_lt32

TRICORE_madd = _ida_allins.TRICORE_madd

TRICORE_madd_f = _ida_allins.TRICORE_madd_f

TRICORE_madd_h = _ida_allins.TRICORE_madd_h

TRICORE_madd_q = _ida_allins.TRICORE_madd_q

TRICORE_madd_u = _ida_allins.TRICORE_madd_u

TRICORE_maddm_h = _ida_allins.TRICORE_maddm_h

TRICORE_maddms_h = _ida_allins.TRICORE_maddms_h

TRICORE_maddr_h = _ida_allins.TRICORE_maddr_h

TRICORE_maddr_q = _ida_allins.TRICORE_maddr_q

TRICORE_maddrs_h = _ida_allins.TRICORE_maddrs_h

TRICORE_maddrs_q = _ida_allins.TRICORE_maddrs_q

TRICORE_madds = _ida_allins.TRICORE_madds

TRICORE_madds_h = _ida_allins.TRICORE_madds_h

TRICORE_madds_q = _ida_allins.TRICORE_madds_q

TRICORE_madds_u = _ida_allins.TRICORE_madds_u

TRICORE_maddsu_h = _ida_allins.TRICORE_maddsu_h

TRICORE_maddsum_h = _ida_allins.TRICORE_maddsum_h

TRICORE_maddsums_h = _ida_allins.TRICORE_maddsums_h

TRICORE_maddsur_h = _ida_allins.TRICORE_maddsur_h

TRICORE_maddsurs_h = _ida_allins.TRICORE_maddsurs_h

TRICORE_maddsus_h = _ida_allins.TRICORE_maddsus_h

TRICORE_max = _ida_allins.TRICORE_max

TRICORE_max_b = _ida_allins.TRICORE_max_b

TRICORE_max_bu = _ida_allins.TRICORE_max_bu

TRICORE_max_h = _ida_allins.TRICORE_max_h

TRICORE_max_hu = _ida_allins.TRICORE_max_hu

TRICORE_max_u = _ida_allins.TRICORE_max_u

TRICORE_mfcr = _ida_allins.TRICORE_mfcr

TRICORE_min = _ida_allins.TRICORE_min

TRICORE_min_b = _ida_allins.TRICORE_min_b

TRICORE_min_bu = _ida_allins.TRICORE_min_bu

TRICORE_min_h = _ida_allins.TRICORE_min_h

TRICORE_min_hu = _ida_allins.TRICORE_min_hu

TRICORE_min_u = _ida_allins.TRICORE_min_u

TRICORE_mov_u = _ida_allins.TRICORE_mov_u

TRICORE_mov16 = _ida_allins.TRICORE_mov16

TRICORE_mov16_a = _ida_allins.TRICORE_mov16_a

TRICORE_mov16_aa = _ida_allins.TRICORE_mov16_aa

TRICORE_mov16_d = _ida_allins.TRICORE_mov16_d

TRICORE_mov32 = _ida_allins.TRICORE_mov32

TRICORE_mov32_a = _ida_allins.TRICORE_mov32_a

TRICORE_mov32_aa = _ida_allins.TRICORE_mov32_aa

TRICORE_mov32_d = _ida_allins.TRICORE_mov32_d

TRICORE_movh = _ida_allins.TRICORE_movh

TRICORE_movh_a = _ida_allins.TRICORE_movh_a

TRICORE_msub = _ida_allins.TRICORE_msub

TRICORE_msub_f = _ida_allins.TRICORE_msub_f

TRICORE_msub_h = _ida_allins.TRICORE_msub_h

TRICORE_msub_q = _ida_allins.TRICORE_msub_q

TRICORE_msub_u = _ida_allins.TRICORE_msub_u

TRICORE_msubad_h = _ida_allins.TRICORE_msubad_h

TRICORE_msubadm_h = _ida_allins.TRICORE_msubadm_h

TRICORE_msubadms_h = _ida_allins.TRICORE_msubadms_h

TRICORE_msubadr_h = _ida_allins.TRICORE_msubadr_h

TRICORE_msubadrs_h = _ida_allins.TRICORE_msubadrs_h

TRICORE_msubads_h = _ida_allins.TRICORE_msubads_h

TRICORE_msubm_h = _ida_allins.TRICORE_msubm_h

TRICORE_msubms_h = _ida_allins.TRICORE_msubms_h

TRICORE_msubr_h = _ida_allins.TRICORE_msubr_h

TRICORE_msubr_q = _ida_allins.TRICORE_msubr_q

TRICORE_msubrs_h = _ida_allins.TRICORE_msubrs_h

TRICORE_msubrs_q = _ida_allins.TRICORE_msubrs_q

TRICORE_msubs = _ida_allins.TRICORE_msubs

TRICORE_msubs_h = _ida_allins.TRICORE_msubs_h

TRICORE_msubs_q = _ida_allins.TRICORE_msubs_q

TRICORE_msubs_u = _ida_allins.TRICORE_msubs_u

TRICORE_mtcr = _ida_allins.TRICORE_mtcr

TRICORE_mul_f = _ida_allins.TRICORE_mul_f

TRICORE_mul_h = _ida_allins.TRICORE_mul_h

TRICORE_mul_q = _ida_allins.TRICORE_mul_q

TRICORE_mul_u = _ida_allins.TRICORE_mul_u

TRICORE_mul16 = _ida_allins.TRICORE_mul16

TRICORE_mul32 = _ida_allins.TRICORE_mul32

TRICORE_mulm_h = _ida_allins.TRICORE_mulm_h

TRICORE_mulms_h = _ida_allins.TRICORE_mulms_h

TRICORE_mulr_h = _ida_allins.TRICORE_mulr_h

TRICORE_mulr_q = _ida_allins.TRICORE_mulr_q

TRICORE_muls = _ida_allins.TRICORE_muls

TRICORE_muls_u = _ida_allins.TRICORE_muls_u

TRICORE_nand = _ida_allins.TRICORE_nand

TRICORE_nand_t = _ida_allins.TRICORE_nand_t

TRICORE_ne = _ida_allins.TRICORE_ne

TRICORE_ne_a = _ida_allins.TRICORE_ne_a

TRICORE_nez_a = _ida_allins.TRICORE_nez_a

TRICORE_nop16 = _ida_allins.TRICORE_nop16

TRICORE_nop32 = _ida_allins.TRICORE_nop32

TRICORE_nor_t = _ida_allins.TRICORE_nor_t

TRICORE_nor16 = _ida_allins.TRICORE_nor16

TRICORE_nor32 = _ida_allins.TRICORE_nor32

TRICORE_or_and_t = _ida_allins.TRICORE_or_and_t

TRICORE_or_andn_t = _ida_allins.TRICORE_or_andn_t

TRICORE_or_eq = _ida_allins.TRICORE_or_eq

TRICORE_or_ge = _ida_allins.TRICORE_or_ge

TRICORE_or_ge_u = _ida_allins.TRICORE_or_ge_u

TRICORE_or_lt = _ida_allins.TRICORE_or_lt

TRICORE_or_lt_u = _ida_allins.TRICORE_or_lt_u

TRICORE_or_ne = _ida_allins.TRICORE_or_ne

TRICORE_or_nor_t = _ida_allins.TRICORE_or_nor_t

TRICORE_or_or_t = _ida_allins.TRICORE_or_or_t

TRICORE_or_t = _ida_allins.TRICORE_or_t

TRICORE_or16 = _ida_allins.TRICORE_or16

TRICORE_or32 = _ida_allins.TRICORE_or32

TRICORE_orn = _ida_allins.TRICORE_orn

TRICORE_orn_t = _ida_allins.TRICORE_orn_t

TRICORE_pack = _ida_allins.TRICORE_pack

TRICORE_parity = _ida_allins.TRICORE_parity

TRICORE_q31tof = _ida_allins.TRICORE_q31tof

TRICORE_qseed_f = _ida_allins.TRICORE_qseed_f

TRICORE_ret16 = _ida_allins.TRICORE_ret16

TRICORE_ret32 = _ida_allins.TRICORE_ret32

TRICORE_rfe16 = _ida_allins.TRICORE_rfe16

TRICORE_rfe32 = _ida_allins.TRICORE_rfe32

TRICORE_rfm = _ida_allins.TRICORE_rfm

TRICORE_rslcx = _ida_allins.TRICORE_rslcx

TRICORE_rstv = _ida_allins.TRICORE_rstv

TRICORE_rsub16 = _ida_allins.TRICORE_rsub16

TRICORE_rsub32 = _ida_allins.TRICORE_rsub32

TRICORE_rsubs = _ida_allins.TRICORE_rsubs

TRICORE_rsubs_u = _ida_allins.TRICORE_rsubs_u

TRICORE_sat16_b = _ida_allins.TRICORE_sat16_b

TRICORE_sat16_bu = _ida_allins.TRICORE_sat16_bu

TRICORE_sat16_h = _ida_allins.TRICORE_sat16_h

TRICORE_sat16_hu = _ida_allins.TRICORE_sat16_hu

TRICORE_sat32_b = _ida_allins.TRICORE_sat32_b

TRICORE_sat32_bu = _ida_allins.TRICORE_sat32_bu

TRICORE_sat32_h = _ida_allins.TRICORE_sat32_h

TRICORE_sat32_hu = _ida_allins.TRICORE_sat32_hu

TRICORE_sel = _ida_allins.TRICORE_sel

TRICORE_seln = _ida_allins.TRICORE_seln

TRICORE_sh_and_t = _ida_allins.TRICORE_sh_and_t

TRICORE_sh_andn_t = _ida_allins.TRICORE_sh_andn_t

TRICORE_sh_eq = _ida_allins.TRICORE_sh_eq

TRICORE_sh_ge = _ida_allins.TRICORE_sh_ge

TRICORE_sh_ge_u = _ida_allins.TRICORE_sh_ge_u

TRICORE_sh_h = _ida_allins.TRICORE_sh_h

TRICORE_sh_lt = _ida_allins.TRICORE_sh_lt

TRICORE_sh_lt_u = _ida_allins.TRICORE_sh_lt_u

TRICORE_sh_nand_t = _ida_allins.TRICORE_sh_nand_t

TRICORE_sh_ne = _ida_allins.TRICORE_sh_ne

TRICORE_sh_nor_t = _ida_allins.TRICORE_sh_nor_t

TRICORE_sh_or_t = _ida_allins.TRICORE_sh_or_t

TRICORE_sh_orn_t = _ida_allins.TRICORE_sh_orn_t

TRICORE_sh_xnor_t = _ida_allins.TRICORE_sh_xnor_t

TRICORE_sh_xor_t = _ida_allins.TRICORE_sh_xor_t

TRICORE_sh16 = _ida_allins.TRICORE_sh16

TRICORE_sh32 = _ida_allins.TRICORE_sh32

TRICORE_sha_h = _ida_allins.TRICORE_sha_h

TRICORE_sha16 = _ida_allins.TRICORE_sha16

TRICORE_sha32 = _ida_allins.TRICORE_sha32

TRICORE_shas = _ida_allins.TRICORE_shas

TRICORE_st_d = _ida_allins.TRICORE_st_d

TRICORE_st_da = _ida_allins.TRICORE_st_da

TRICORE_st_q = _ida_allins.TRICORE_st_q

TRICORE_st_t = _ida_allins.TRICORE_st_t

TRICORE_st16_a = _ida_allins.TRICORE_st16_a

TRICORE_st16_b = _ida_allins.TRICORE_st16_b

TRICORE_st16_h = _ida_allins.TRICORE_st16_h

TRICORE_st16_w = _ida_allins.TRICORE_st16_w

TRICORE_st32_a = _ida_allins.TRICORE_st32_a

TRICORE_st32_b = _ida_allins.TRICORE_st32_b

TRICORE_st32_h = _ida_allins.TRICORE_st32_h

TRICORE_st32_w = _ida_allins.TRICORE_st32_w

TRICORE_stlcx = _ida_allins.TRICORE_stlcx

TRICORE_stucx = _ida_allins.TRICORE_stucx

TRICORE_sub_b = _ida_allins.TRICORE_sub_b

TRICORE_sub_f = _ida_allins.TRICORE_sub_f

TRICORE_sub_h = _ida_allins.TRICORE_sub_h

TRICORE_sub16 = _ida_allins.TRICORE_sub16

TRICORE_sub16_a = _ida_allins.TRICORE_sub16_a

TRICORE_sub32 = _ida_allins.TRICORE_sub32

TRICORE_sub32_a = _ida_allins.TRICORE_sub32_a

TRICORE_subc = _ida_allins.TRICORE_subc

TRICORE_subs_h = _ida_allins.TRICORE_subs_h

TRICORE_subs_hu = _ida_allins.TRICORE_subs_hu

TRICORE_subs_u = _ida_allins.TRICORE_subs_u

TRICORE_subs16 = _ida_allins.TRICORE_subs16

TRICORE_subs32 = _ida_allins.TRICORE_subs32

TRICORE_subx = _ida_allins.TRICORE_subx

TRICORE_svlcx = _ida_allins.TRICORE_svlcx

TRICORE_swap_w = _ida_allins.TRICORE_swap_w

TRICORE_syscall = _ida_allins.TRICORE_syscall

TRICORE_tlbdemap = _ida_allins.TRICORE_tlbdemap

TRICORE_tlbflush_a = _ida_allins.TRICORE_tlbflush_a

TRICORE_tlbflush_b = _ida_allins.TRICORE_tlbflush_b

TRICORE_tlbmap = _ida_allins.TRICORE_tlbmap

TRICORE_tlbprobe_a = _ida_allins.TRICORE_tlbprobe_a

TRICORE_tlbprobe_i = _ida_allins.TRICORE_tlbprobe_i

TRICORE_trapsv = _ida_allins.TRICORE_trapsv

TRICORE_trapv = _ida_allins.TRICORE_trapv

TRICORE_unpack = _ida_allins.TRICORE_unpack

TRICORE_updfl = _ida_allins.TRICORE_updfl

TRICORE_utof = _ida_allins.TRICORE_utof

TRICORE_xnor = _ida_allins.TRICORE_xnor

TRICORE_xnor_t = _ida_allins.TRICORE_xnor_t

TRICORE_xor_eq = _ida_allins.TRICORE_xor_eq

TRICORE_xor_ge = _ida_allins.TRICORE_xor_ge

TRICORE_xor_ge_u = _ida_allins.TRICORE_xor_ge_u

TRICORE_xor_lt = _ida_allins.TRICORE_xor_lt

TRICORE_xor_lt_u = _ida_allins.TRICORE_xor_lt_u

TRICORE_xor_ne = _ida_allins.TRICORE_xor_ne

TRICORE_xor_t = _ida_allins.TRICORE_xor_t

TRICORE_xor16 = _ida_allins.TRICORE_xor16

TRICORE_xor32 = _ida_allins.TRICORE_xor32

TRICORE_cachei_i = _ida_allins.TRICORE_cachei_i

TRICORE_cachei_w = _ida_allins.TRICORE_cachei_w

TRICORE_cachei_wi = _ida_allins.TRICORE_cachei_wi

TRICORE_div = _ida_allins.TRICORE_div

TRICORE_div_u = _ida_allins.TRICORE_div_u

TRICORE_fcall = _ida_allins.TRICORE_fcall

TRICORE_fcalla = _ida_allins.TRICORE_fcalla

TRICORE_fcalli = _ida_allins.TRICORE_fcalli

TRICORE_fret16 = _ida_allins.TRICORE_fret16

TRICORE_fret32 = _ida_allins.TRICORE_fret32

TRICORE_ftoiz = _ida_allins.TRICORE_ftoiz

TRICORE_ftoq31z = _ida_allins.TRICORE_ftoq31z

TRICORE_ftouz = _ida_allins.TRICORE_ftouz

TRICORE_restore = _ida_allins.TRICORE_restore

TRICORE_crc32 = _ida_allins.TRICORE_crc32

TRICORE_wait = _ida_allins.TRICORE_wait

TRICORE_cmpswap_w = _ida_allins.TRICORE_cmpswap_w

TRICORE_swapmsk_w = _ida_allins.TRICORE_swapmsk_w

TRICORE_crc32_b = _ida_allins.TRICORE_crc32_b

TRICORE_crc32l_w = _ida_allins.TRICORE_crc32l_w

TRICORE_crcn = _ida_allins.TRICORE_crcn

TRICORE_shuffle = _ida_allins.TRICORE_shuffle

TRICORE_popcnt_w = _ida_allins.TRICORE_popcnt_w

TRICORE_lha = _ida_allins.TRICORE_lha

TRICORE_last = _ida_allins.TRICORE_last

ARC_null = _ida_allins.ARC_null

ARC_ld = _ida_allins.ARC_ld

ARC_lr = _ida_allins.ARC_lr

ARC_st = _ida_allins.ARC_st

ARC_sr = _ida_allins.ARC_sr

ARC_store_instructions = _ida_allins.ARC_store_instructions

ARC_flag = _ida_allins.ARC_flag

ARC_asr = _ida_allins.ARC_asr

ARC_lsr = _ida_allins.ARC_lsr

ARC_sexb = _ida_allins.ARC_sexb

ARC_sexw = _ida_allins.ARC_sexw

ARC_sexh = _ida_allins.ARC_sexh

ARC_extb = _ida_allins.ARC_extb

ARC_extw = _ida_allins.ARC_extw

ARC_exth = _ida_allins.ARC_exth

ARC_ror = _ida_allins.ARC_ror

ARC_rrc = _ida_allins.ARC_rrc

ARC_b = _ida_allins.ARC_b

ARC_bl = _ida_allins.ARC_bl

ARC_lp = _ida_allins.ARC_lp

ARC_j = _ida_allins.ARC_j

ARC_jl = _ida_allins.ARC_jl

ARC_add = _ida_allins.ARC_add

ARC_adc = _ida_allins.ARC_adc

ARC_sub = _ida_allins.ARC_sub

ARC_sbc = _ida_allins.ARC_sbc

ARC_and = _ida_allins.ARC_and

ARC_or = _ida_allins.ARC_or

ARC_bic = _ida_allins.ARC_bic

ARC_xor = _ida_allins.ARC_xor

ARC_mov = _ida_allins.ARC_mov

ARC_nop = _ida_allins.ARC_nop

ARC_lsl = _ida_allins.ARC_lsl

ARC_rlc = _ida_allins.ARC_rlc

ARC_brk = _ida_allins.ARC_brk

ARC_sleep = _ida_allins.ARC_sleep

ARC_swi = _ida_allins.ARC_swi

ARC_asl = _ida_allins.ARC_asl

ARC_mul64 = _ida_allins.ARC_mul64

ARC_mulu64 = _ida_allins.ARC_mulu64

ARC_max = _ida_allins.ARC_max

ARC_min = _ida_allins.ARC_min

ARC_swap = _ida_allins.ARC_swap

ARC_norm = _ida_allins.ARC_norm

ARC_bbit0 = _ida_allins.ARC_bbit0

ARC_bbit1 = _ida_allins.ARC_bbit1

ARC_br = _ida_allins.ARC_br

ARC_pop = _ida_allins.ARC_pop

ARC_push = _ida_allins.ARC_push

ARC_abs = _ida_allins.ARC_abs

ARC_add1 = _ida_allins.ARC_add1

ARC_add2 = _ida_allins.ARC_add2

ARC_add3 = _ida_allins.ARC_add3

ARC_bclr = _ida_allins.ARC_bclr

ARC_bmsk = _ida_allins.ARC_bmsk

ARC_bset = _ida_allins.ARC_bset

ARC_btst = _ida_allins.ARC_btst

ARC_bxor = _ida_allins.ARC_bxor

ARC_cmp = _ida_allins.ARC_cmp

ARC_ex = _ida_allins.ARC_ex

ARC_mpy = _ida_allins.ARC_mpy

ARC_mpyh = _ida_allins.ARC_mpyh

ARC_mpym = _ida_allins.ARC_mpym

ARC_mpyhu = _ida_allins.ARC_mpyhu

ARC_mpyhm = _ida_allins.ARC_mpyhm

ARC_mpyu = _ida_allins.ARC_mpyu

ARC_neg = _ida_allins.ARC_neg

ARC_not = _ida_allins.ARC_not

ARC_rcmp = _ida_allins.ARC_rcmp

ARC_rsub = _ida_allins.ARC_rsub

ARC_rtie = _ida_allins.ARC_rtie

ARC_sub1 = _ida_allins.ARC_sub1

ARC_sub2 = _ida_allins.ARC_sub2

ARC_sub3 = _ida_allins.ARC_sub3

ARC_sync = _ida_allins.ARC_sync

ARC_trap = _ida_allins.ARC_trap

ARC_tst = _ida_allins.ARC_tst

ARC_unimp = _ida_allins.ARC_unimp

ARC_abss = _ida_allins.ARC_abss

ARC_abssw = _ida_allins.ARC_abssw

ARC_abssh = _ida_allins.ARC_abssh

ARC_adds = _ida_allins.ARC_adds

ARC_addsdw = _ida_allins.ARC_addsdw

ARC_asls = _ida_allins.ARC_asls

ARC_asrs = _ida_allins.ARC_asrs

ARC_divaw = _ida_allins.ARC_divaw

ARC_negs = _ida_allins.ARC_negs

ARC_negsw = _ida_allins.ARC_negsw

ARC_negsh = _ida_allins.ARC_negsh

ARC_normw = _ida_allins.ARC_normw

ARC_normh = _ida_allins.ARC_normh

ARC_rnd16 = _ida_allins.ARC_rnd16

ARC_rndh = _ida_allins.ARC_rndh

ARC_sat16 = _ida_allins.ARC_sat16

ARC_sath = _ida_allins.ARC_sath

ARC_subs = _ida_allins.ARC_subs

ARC_subsdw = _ida_allins.ARC_subsdw

ARC_muldw = _ida_allins.ARC_muldw

ARC_muludw = _ida_allins.ARC_muludw

ARC_mulrdw = _ida_allins.ARC_mulrdw

ARC_macdw = _ida_allins.ARC_macdw

ARC_macudw = _ida_allins.ARC_macudw

ARC_macrdw = _ida_allins.ARC_macrdw

ARC_msubdw = _ida_allins.ARC_msubdw

ARC_mululw = _ida_allins.ARC_mululw

ARC_mullw = _ida_allins.ARC_mullw

ARC_mulflw = _ida_allins.ARC_mulflw

ARC_maclw = _ida_allins.ARC_maclw

ARC_macflw = _ida_allins.ARC_macflw

ARC_machulw = _ida_allins.ARC_machulw

ARC_machlw = _ida_allins.ARC_machlw

ARC_machflw = _ida_allins.ARC_machflw

ARC_mulhlw = _ida_allins.ARC_mulhlw

ARC_mulhflw = _ida_allins.ARC_mulhflw

ARC_acm = _ida_allins.ARC_acm

ARC_addqbs = _ida_allins.ARC_addqbs

ARC_avgqb = _ida_allins.ARC_avgqb

ARC_clamp = _ida_allins.ARC_clamp

ARC_daddh11 = _ida_allins.ARC_daddh11

ARC_daddh12 = _ida_allins.ARC_daddh12

ARC_daddh21 = _ida_allins.ARC_daddh21

ARC_daddh22 = _ida_allins.ARC_daddh22

ARC_dexcl1 = _ida_allins.ARC_dexcl1

ARC_dexcl2 = _ida_allins.ARC_dexcl2

ARC_dmulh11 = _ida_allins.ARC_dmulh11

ARC_dmulh12 = _ida_allins.ARC_dmulh12

ARC_dmulh21 = _ida_allins.ARC_dmulh21

ARC_dmulh22 = _ida_allins.ARC_dmulh22

ARC_dsubh11 = _ida_allins.ARC_dsubh11

ARC_dsubh12 = _ida_allins.ARC_dsubh12

ARC_dsubh21 = _ida_allins.ARC_dsubh21

ARC_dsubh22 = _ida_allins.ARC_dsubh22

ARC_drsubh11 = _ida_allins.ARC_drsubh11

ARC_drsubh12 = _ida_allins.ARC_drsubh12

ARC_drsubh21 = _ida_allins.ARC_drsubh21

ARC_drsubh22 = _ida_allins.ARC_drsubh22

ARC_fadd = _ida_allins.ARC_fadd

ARC_fsadd = _ida_allins.ARC_fsadd

ARC_fmul = _ida_allins.ARC_fmul

ARC_fsmul = _ida_allins.ARC_fsmul

ARC_fsub = _ida_allins.ARC_fsub

ARC_fssub = _ida_allins.ARC_fssub

ARC_fxtr = _ida_allins.ARC_fxtr

ARC_iaddr = _ida_allins.ARC_iaddr

ARC_mpyqb = _ida_allins.ARC_mpyqb

ARC_sfxtr = _ida_allins.ARC_sfxtr

ARC_pkqb = _ida_allins.ARC_pkqb

ARC_upkqb = _ida_allins.ARC_upkqb

ARC_xpkqb = _ida_allins.ARC_xpkqb

ARC_mpyw = _ida_allins.ARC_mpyw

ARC_mpyuw = _ida_allins.ARC_mpyuw

ARC_bi = _ida_allins.ARC_bi

ARC_bih = _ida_allins.ARC_bih

ARC_ldi = _ida_allins.ARC_ldi

ARC_aex = _ida_allins.ARC_aex

ARC_bmskn = _ida_allins.ARC_bmskn

ARC_seteq = _ida_allins.ARC_seteq

ARC_setne = _ida_allins.ARC_setne

ARC_setlt = _ida_allins.ARC_setlt

ARC_setge = _ida_allins.ARC_setge

ARC_setlo = _ida_allins.ARC_setlo

ARC_seths = _ida_allins.ARC_seths

ARC_setle = _ida_allins.ARC_setle

ARC_setgt = _ida_allins.ARC_setgt

ARC_rol = _ida_allins.ARC_rol

ARC_llock = _ida_allins.ARC_llock

ARC_scond = _ida_allins.ARC_scond

ARC_seti = _ida_allins.ARC_seti

ARC_clri = _ida_allins.ARC_clri

ARC_enter = _ida_allins.ARC_enter

ARC_leave = _ida_allins.ARC_leave

ARC_div = _ida_allins.ARC_div

ARC_divu = _ida_allins.ARC_divu

ARC_rem = _ida_allins.ARC_rem

ARC_remu = _ida_allins.ARC_remu

ARC_asrsr = _ida_allins.ARC_asrsr

ARC_valgn2h = _ida_allins.ARC_valgn2h

ARC_setacc = _ida_allins.ARC_setacc

ARC_mac = _ida_allins.ARC_mac

ARC_macu = _ida_allins.ARC_macu

ARC_dmpyh = _ida_allins.ARC_dmpyh

ARC_dmpyhu = _ida_allins.ARC_dmpyhu

ARC_dmach = _ida_allins.ARC_dmach

ARC_dmachu = _ida_allins.ARC_dmachu

ARC_vadd2h = _ida_allins.ARC_vadd2h

ARC_vadds2h = _ida_allins.ARC_vadds2h

ARC_vsub2h = _ida_allins.ARC_vsub2h

ARC_vsubs2h = _ida_allins.ARC_vsubs2h

ARC_vaddsub2h = _ida_allins.ARC_vaddsub2h

ARC_vaddsubs2h = _ida_allins.ARC_vaddsubs2h

ARC_vsubadd2h = _ida_allins.ARC_vsubadd2h

ARC_vsubadds2h = _ida_allins.ARC_vsubadds2h

ARC_mpyd = _ida_allins.ARC_mpyd

ARC_mpydu = _ida_allins.ARC_mpydu

ARC_macd = _ida_allins.ARC_macd

ARC_macdu = _ida_allins.ARC_macdu

ARC_vmpy2h = _ida_allins.ARC_vmpy2h

ARC_vmpy2hf = _ida_allins.ARC_vmpy2hf

ARC_vmpy2hu = _ida_allins.ARC_vmpy2hu

ARC_vmpy2hfr = _ida_allins.ARC_vmpy2hfr

ARC_vmac2h = _ida_allins.ARC_vmac2h

ARC_vmac2hf = _ida_allins.ARC_vmac2hf

ARC_vmac2hu = _ida_allins.ARC_vmac2hu

ARC_vmac2hfr = _ida_allins.ARC_vmac2hfr

ARC_vmpy2hwf = _ida_allins.ARC_vmpy2hwf

ARC_vasl2h = _ida_allins.ARC_vasl2h

ARC_vasls2h = _ida_allins.ARC_vasls2h

ARC_vasr2h = _ida_allins.ARC_vasr2h

ARC_vasrs2h = _ida_allins.ARC_vasrs2h

ARC_vlsr2h = _ida_allins.ARC_vlsr2h

ARC_vasrsr2h = _ida_allins.ARC_vasrsr2h

ARC_vadd4b = _ida_allins.ARC_vadd4b

ARC_vmax2h = _ida_allins.ARC_vmax2h

ARC_vsub4b = _ida_allins.ARC_vsub4b

ARC_vmin2h = _ida_allins.ARC_vmin2h

ARC_adcs = _ida_allins.ARC_adcs

ARC_sbcs = _ida_allins.ARC_sbcs

ARC_dmpyhwf = _ida_allins.ARC_dmpyhwf

ARC_vpack2hl = _ida_allins.ARC_vpack2hl

ARC_vpack2hm = _ida_allins.ARC_vpack2hm

ARC_dmpyhf = _ida_allins.ARC_dmpyhf

ARC_dmpyhfr = _ida_allins.ARC_dmpyhfr

ARC_dmachf = _ida_allins.ARC_dmachf

ARC_dmachfr = _ida_allins.ARC_dmachfr

ARC_vperm = _ida_allins.ARC_vperm

ARC_bspush = _ida_allins.ARC_bspush

ARC_swape = _ida_allins.ARC_swape

ARC_lsl16 = _ida_allins.ARC_lsl16

ARC_lsr16 = _ida_allins.ARC_lsr16

ARC_asr16 = _ida_allins.ARC_asr16

ARC_asr8 = _ida_allins.ARC_asr8

ARC_lsr8 = _ida_allins.ARC_lsr8

ARC_lsl8 = _ida_allins.ARC_lsl8

ARC_rol8 = _ida_allins.ARC_rol8

ARC_ror8 = _ida_allins.ARC_ror8

ARC_ffs = _ida_allins.ARC_ffs

ARC_fls = _ida_allins.ARC_fls

ARC_getacc = _ida_allins.ARC_getacc

ARC_normacc = _ida_allins.ARC_normacc

ARC_satf = _ida_allins.ARC_satf

ARC_vpack2hbl = _ida_allins.ARC_vpack2hbl

ARC_vpack2hbm = _ida_allins.ARC_vpack2hbm

ARC_vpack2hblf = _ida_allins.ARC_vpack2hblf

ARC_vpack2hbmf = _ida_allins.ARC_vpack2hbmf

ARC_vext2bhlf = _ida_allins.ARC_vext2bhlf

ARC_vext2bhmf = _ida_allins.ARC_vext2bhmf

ARC_vrep2hl = _ida_allins.ARC_vrep2hl

ARC_vrep2hm = _ida_allins.ARC_vrep2hm

ARC_vext2bhl = _ida_allins.ARC_vext2bhl

ARC_vext2bhm = _ida_allins.ARC_vext2bhm

ARC_vsext2bhl = _ida_allins.ARC_vsext2bhl

ARC_vsext2bhm = _ida_allins.ARC_vsext2bhm

ARC_vabs2h = _ida_allins.ARC_vabs2h

ARC_vabss2h = _ida_allins.ARC_vabss2h

ARC_vneg2h = _ida_allins.ARC_vneg2h

ARC_vnegs2h = _ida_allins.ARC_vnegs2h

ARC_vnorm2h = _ida_allins.ARC_vnorm2h

ARC_bspeek = _ida_allins.ARC_bspeek

ARC_bspop = _ida_allins.ARC_bspop

ARC_sqrt = _ida_allins.ARC_sqrt

ARC_sqrtf = _ida_allins.ARC_sqrtf

ARC_aslacc = _ida_allins.ARC_aslacc

ARC_aslsacc = _ida_allins.ARC_aslsacc

ARC_flagacc = _ida_allins.ARC_flagacc

ARC_modif = _ida_allins.ARC_modif

ARC_cmpyhnfr = _ida_allins.ARC_cmpyhnfr

ARC_cmpyhfr = _ida_allins.ARC_cmpyhfr

ARC_cmpychfr = _ida_allins.ARC_cmpychfr

ARC_vmsub2hf = _ida_allins.ARC_vmsub2hf

ARC_vmsub2hfr = _ida_allins.ARC_vmsub2hfr

ARC_cmpychnfr = _ida_allins.ARC_cmpychnfr

ARC_cmachnfr = _ida_allins.ARC_cmachnfr

ARC_cmachfr = _ida_allins.ARC_cmachfr

ARC_cmacchnfr = _ida_allins.ARC_cmacchnfr

ARC_cmacchfr = _ida_allins.ARC_cmacchfr

ARC_mpyf = _ida_allins.ARC_mpyf

ARC_mpyfr = _ida_allins.ARC_mpyfr

ARC_macf = _ida_allins.ARC_macf

ARC_macfr = _ida_allins.ARC_macfr

ARC_msubf = _ida_allins.ARC_msubf

ARC_msubfr = _ida_allins.ARC_msubfr

ARC_divf = _ida_allins.ARC_divf

ARC_vmac2hnfr = _ida_allins.ARC_vmac2hnfr

ARC_vmsub2hnfr = _ida_allins.ARC_vmsub2hnfr

ARC_mpydf = _ida_allins.ARC_mpydf

ARC_macdf = _ida_allins.ARC_macdf

ARC_msubwhfl = _ida_allins.ARC_msubwhfl

ARC_msubdf = _ida_allins.ARC_msubdf

ARC_dmpyhbl = _ida_allins.ARC_dmpyhbl

ARC_dmpyhbm = _ida_allins.ARC_dmpyhbm

ARC_dmachbl = _ida_allins.ARC_dmachbl

ARC_dmachbm = _ida_allins.ARC_dmachbm

ARC_msubwhflr = _ida_allins.ARC_msubwhflr

ARC_cmpyhfmr = _ida_allins.ARC_cmpyhfmr

ARC_cbflyhf0r = _ida_allins.ARC_cbflyhf0r

ARC_mpywhl = _ida_allins.ARC_mpywhl

ARC_macwhl = _ida_allins.ARC_macwhl

ARC_mpywhul = _ida_allins.ARC_mpywhul

ARC_macwhul = _ida_allins.ARC_macwhul

ARC_mpywhfm = _ida_allins.ARC_mpywhfm

ARC_mpywhfmr = _ida_allins.ARC_mpywhfmr

ARC_macwhfm = _ida_allins.ARC_macwhfm

ARC_macwhfmr = _ida_allins.ARC_macwhfmr

ARC_mpywhfl = _ida_allins.ARC_mpywhfl

ARC_mpywhflr = _ida_allins.ARC_mpywhflr

ARC_macwhfl = _ida_allins.ARC_macwhfl

ARC_macwhflr = _ida_allins.ARC_macwhflr

ARC_macwhkl = _ida_allins.ARC_macwhkl

ARC_macwhkul = _ida_allins.ARC_macwhkul

ARC_mpywhkl = _ida_allins.ARC_mpywhkl

ARC_mpywhkul = _ida_allins.ARC_mpywhkul

ARC_msubwhfm = _ida_allins.ARC_msubwhfm

ARC_msubwhfmr = _ida_allins.ARC_msubwhfmr

ARC_cbflyhf1r = _ida_allins.ARC_cbflyhf1r

ARC_fscmp = _ida_allins.ARC_fscmp

ARC_fscmpf = _ida_allins.ARC_fscmpf

ARC_fsmadd = _ida_allins.ARC_fsmadd

ARC_fsmsub = _ida_allins.ARC_fsmsub

ARC_fsdiv = _ida_allins.ARC_fsdiv

ARC_fcvt32 = _ida_allins.ARC_fcvt32

ARC_fssqrt = _ida_allins.ARC_fssqrt

ARC_jli = _ida_allins.ARC_jli

ARC_ei = _ida_allins.ARC_ei

ARC_kflag = _ida_allins.ARC_kflag

ARC_wevt = _ida_allins.ARC_wevt

ARC_last = _ida_allins.ARC_last

TMS28_null = _ida_allins.TMS28_null

TMS28_aborti = _ida_allins.TMS28_aborti

TMS28_abs = _ida_allins.TMS28_abs

TMS28_abstc = _ida_allins.TMS28_abstc

TMS28_add = _ida_allins.TMS28_add

TMS28_addb = _ida_allins.TMS28_addb

TMS28_addcl = _ida_allins.TMS28_addcl

TMS28_addcu = _ida_allins.TMS28_addcu

TMS28_addl = _ida_allins.TMS28_addl

TMS28_addu = _ida_allins.TMS28_addu

TMS28_addul = _ida_allins.TMS28_addul

TMS28_adrk = _ida_allins.TMS28_adrk

TMS28_and = _ida_allins.TMS28_and

TMS28_andb = _ida_allins.TMS28_andb

TMS28_asp = _ida_allins.TMS28_asp

TMS28_asr = _ida_allins.TMS28_asr

TMS28_asr64 = _ida_allins.TMS28_asr64

TMS28_asrl = _ida_allins.TMS28_asrl

TMS28_b = _ida_allins.TMS28_b

TMS28_banz = _ida_allins.TMS28_banz

TMS28_bar = _ida_allins.TMS28_bar

TMS28_bf = _ida_allins.TMS28_bf

TMS28_c27map = _ida_allins.TMS28_c27map

TMS28_c27obj = _ida_allins.TMS28_c27obj

TMS28_c28addr = _ida_allins.TMS28_c28addr

TMS28_c28map = _ida_allins.TMS28_c28map

TMS28_c28obj = _ida_allins.TMS28_c28obj

TMS28_clrc = _ida_allins.TMS28_clrc

TMS28_cmp = _ida_allins.TMS28_cmp

TMS28_cmp64 = _ida_allins.TMS28_cmp64

TMS28_cmpb = _ida_allins.TMS28_cmpb

TMS28_cmpl = _ida_allins.TMS28_cmpl

TMS28_cmpr = _ida_allins.TMS28_cmpr

TMS28_csb = _ida_allins.TMS28_csb

TMS28_dec = _ida_allins.TMS28_dec

TMS28_dint = _ida_allins.TMS28_dint

TMS28_dmac = _ida_allins.TMS28_dmac

TMS28_dmov = _ida_allins.TMS28_dmov

TMS28_eallow = _ida_allins.TMS28_eallow

TMS28_edis = _ida_allins.TMS28_edis

TMS28_eint = _ida_allins.TMS28_eint

TMS28_estop0 = _ida_allins.TMS28_estop0

TMS28_estop1 = _ida_allins.TMS28_estop1

TMS28_ffc = _ida_allins.TMS28_ffc

TMS28_flip = _ida_allins.TMS28_flip

TMS28_iack = _ida_allins.TMS28_iack

TMS28_idle = _ida_allins.TMS28_idle

TMS28_imacl = _ida_allins.TMS28_imacl

TMS28_impyal = _ida_allins.TMS28_impyal

TMS28_impyl = _ida_allins.TMS28_impyl

TMS28_impysl = _ida_allins.TMS28_impysl

TMS28_impyxul = _ida_allins.TMS28_impyxul

TMS28_in = _ida_allins.TMS28_in

TMS28_inc = _ida_allins.TMS28_inc

TMS28_intr = _ida_allins.TMS28_intr

TMS28_iret = _ida_allins.TMS28_iret

TMS28_lb = _ida_allins.TMS28_lb

TMS28_lc = _ida_allins.TMS28_lc

TMS28_lcr = _ida_allins.TMS28_lcr

TMS28_loopnz = _ida_allins.TMS28_loopnz

TMS28_loopz = _ida_allins.TMS28_loopz

TMS28_lpaddr = _ida_allins.TMS28_lpaddr

TMS28_lret = _ida_allins.TMS28_lret

TMS28_lrete = _ida_allins.TMS28_lrete

TMS28_lretr = _ida_allins.TMS28_lretr

TMS28_lsl = _ida_allins.TMS28_lsl

TMS28_lsl64 = _ida_allins.TMS28_lsl64

TMS28_lsll = _ida_allins.TMS28_lsll

TMS28_lsr = _ida_allins.TMS28_lsr

TMS28_lsr64 = _ida_allins.TMS28_lsr64

TMS28_lsrl = _ida_allins.TMS28_lsrl

TMS28_mac = _ida_allins.TMS28_mac

TMS28_max = _ida_allins.TMS28_max

TMS28_maxcul = _ida_allins.TMS28_maxcul

TMS28_maxl = _ida_allins.TMS28_maxl

TMS28_min = _ida_allins.TMS28_min

TMS28_mincul = _ida_allins.TMS28_mincul

TMS28_minl = _ida_allins.TMS28_minl

TMS28_mov = _ida_allins.TMS28_mov

TMS28_mova = _ida_allins.TMS28_mova

TMS28_movad = _ida_allins.TMS28_movad

TMS28_movb = _ida_allins.TMS28_movb

TMS28_movdl = _ida_allins.TMS28_movdl

TMS28_movh = _ida_allins.TMS28_movh

TMS28_movl = _ida_allins.TMS28_movl

TMS28_movp = _ida_allins.TMS28_movp

TMS28_movs = _ida_allins.TMS28_movs

TMS28_movu = _ida_allins.TMS28_movu

TMS28_movw = _ida_allins.TMS28_movw

TMS28_movx = _ida_allins.TMS28_movx

TMS28_movz = _ida_allins.TMS28_movz

TMS28_mpy = _ida_allins.TMS28_mpy

TMS28_mpya = _ida_allins.TMS28_mpya

TMS28_mpyb = _ida_allins.TMS28_mpyb

TMS28_mpys = _ida_allins.TMS28_mpys

TMS28_mpyu = _ida_allins.TMS28_mpyu

TMS28_mpyxu = _ida_allins.TMS28_mpyxu

TMS28_nasp = _ida_allins.TMS28_nasp

TMS28_neg = _ida_allins.TMS28_neg

TMS28_neg64 = _ida_allins.TMS28_neg64

TMS28_negtc = _ida_allins.TMS28_negtc

TMS28_nop = _ida_allins.TMS28_nop

TMS28_norm = _ida_allins.TMS28_norm

TMS28_not = _ida_allins.TMS28_not

TMS28_or = _ida_allins.TMS28_or

TMS28_orb = _ida_allins.TMS28_orb

TMS28_out = _ida_allins.TMS28_out

TMS28_pop = _ida_allins.TMS28_pop

TMS28_pread = _ida_allins.TMS28_pread

TMS28_push = _ida_allins.TMS28_push

TMS28_pwrite = _ida_allins.TMS28_pwrite

TMS28_qmacl = _ida_allins.TMS28_qmacl

TMS28_qmpyal = _ida_allins.TMS28_qmpyal

TMS28_qmpyl = _ida_allins.TMS28_qmpyl

TMS28_qmpysl = _ida_allins.TMS28_qmpysl

TMS28_qmpyul = _ida_allins.TMS28_qmpyul

TMS28_qmpyxul = _ida_allins.TMS28_qmpyxul

TMS28_rol = _ida_allins.TMS28_rol

TMS28_ror = _ida_allins.TMS28_ror

TMS28_rpt = _ida_allins.TMS28_rpt

TMS28_sat = _ida_allins.TMS28_sat

TMS28_sat64 = _ida_allins.TMS28_sat64

TMS28_sb = _ida_allins.TMS28_sb

TMS28_sbbu = _ida_allins.TMS28_sbbu

TMS28_sbf = _ida_allins.TMS28_sbf

TMS28_sbrk = _ida_allins.TMS28_sbrk

TMS28_setc = _ida_allins.TMS28_setc

TMS28_sfr = _ida_allins.TMS28_sfr

TMS28_spm = _ida_allins.TMS28_spm

TMS28_sqra = _ida_allins.TMS28_sqra

TMS28_sqrs = _ida_allins.TMS28_sqrs

TMS28_sub = _ida_allins.TMS28_sub

TMS28_subb = _ida_allins.TMS28_subb

TMS28_subbl = _ida_allins.TMS28_subbl

TMS28_subcu = _ida_allins.TMS28_subcu

TMS28_subcul = _ida_allins.TMS28_subcul

TMS28_subl = _ida_allins.TMS28_subl

TMS28_subr = _ida_allins.TMS28_subr

TMS28_subrl = _ida_allins.TMS28_subrl

TMS28_subu = _ida_allins.TMS28_subu

TMS28_subul = _ida_allins.TMS28_subul

TMS28_sxtb = _ida_allins.TMS28_sxtb

TMS28_tbit = _ida_allins.TMS28_tbit

TMS28_tclr = _ida_allins.TMS28_tclr

TMS28_test = _ida_allins.TMS28_test

TMS28_trap = _ida_allins.TMS28_trap

TMS28_tset = _ida_allins.TMS28_tset

TMS28_uout = _ida_allins.TMS28_uout

TMS28_xb = _ida_allins.TMS28_xb

TMS28_xbanz = _ida_allins.TMS28_xbanz

TMS28_xcall = _ida_allins.TMS28_xcall

TMS28_xmac = _ida_allins.TMS28_xmac

TMS28_xmacd = _ida_allins.TMS28_xmacd

TMS28_xor = _ida_allins.TMS28_xor

TMS28_xorb = _ida_allins.TMS28_xorb

TMS28_xpread = _ida_allins.TMS28_xpread

TMS28_xpwrite = _ida_allins.TMS28_xpwrite

TMS28_xret = _ida_allins.TMS28_xret

TMS28_xretc = _ida_allins.TMS28_xretc

TMS28_zalr = _ida_allins.TMS28_zalr

TMS28_zap = _ida_allins.TMS28_zap

TMS28_zapa = _ida_allins.TMS28_zapa

TMS28_last = _ida_allins.TMS28_last

UNSP_null = _ida_allins.UNSP_null

UNSP_add = _ida_allins.UNSP_add

UNSP_adc = _ida_allins.UNSP_adc

UNSP_sub = _ida_allins.UNSP_sub

UNSP_sbc = _ida_allins.UNSP_sbc

UNSP_cmp = _ida_allins.UNSP_cmp

UNSP_cmpc = _ida_allins.UNSP_cmpc

UNSP_neg = _ida_allins.UNSP_neg

UNSP_negc = _ida_allins.UNSP_negc

UNSP_xor = _ida_allins.UNSP_xor

UNSP_load = _ida_allins.UNSP_load

UNSP_or = _ida_allins.UNSP_or

UNSP_and = _ida_allins.UNSP_and

UNSP_test = _ida_allins.UNSP_test

UNSP_store = _ida_allins.UNSP_store

UNSP_add_s = _ida_allins.UNSP_add_s

UNSP_adc_s = _ida_allins.UNSP_adc_s

UNSP_sub_s = _ida_allins.UNSP_sub_s

UNSP_sbc_s = _ida_allins.UNSP_sbc_s

UNSP_cmp_s = _ida_allins.UNSP_cmp_s

UNSP_cmpc_s = _ida_allins.UNSP_cmpc_s

UNSP_neg_s = _ida_allins.UNSP_neg_s

UNSP_negc_s = _ida_allins.UNSP_negc_s

UNSP_xor_s = _ida_allins.UNSP_xor_s

UNSP_load_s = _ida_allins.UNSP_load_s

UNSP_or_s = _ida_allins.UNSP_or_s

UNSP_and_s = _ida_allins.UNSP_and_s

UNSP_test_s = _ida_allins.UNSP_test_s

UNSP_store_s = _ida_allins.UNSP_store_s

UNSP_retf = _ida_allins.UNSP_retf

UNSP_reti = _ida_allins.UNSP_reti

UNSP_pop = _ida_allins.UNSP_pop

UNSP_push = _ida_allins.UNSP_push

UNSP_call = _ida_allins.UNSP_call

UNSP_goto = _ida_allins.UNSP_goto

UNSP_nop = _ida_allins.UNSP_nop

UNSP_exp = _ida_allins.UNSP_exp

UNSP_jb = _ida_allins.UNSP_jb

UNSP_jae = _ida_allins.UNSP_jae

UNSP_jge = _ida_allins.UNSP_jge

UNSP_jl = _ida_allins.UNSP_jl

UNSP_jne = _ida_allins.UNSP_jne

UNSP_je = _ida_allins.UNSP_je

UNSP_jpl = _ida_allins.UNSP_jpl

UNSP_jmi = _ida_allins.UNSP_jmi

UNSP_jbe = _ida_allins.UNSP_jbe

UNSP_ja = _ida_allins.UNSP_ja

UNSP_jle = _ida_allins.UNSP_jle

UNSP_jg = _ida_allins.UNSP_jg

UNSP_jvc = _ida_allins.UNSP_jvc

UNSP_jvs = _ida_allins.UNSP_jvs

UNSP_jmp = _ida_allins.UNSP_jmp

UNSP_mulss = _ida_allins.UNSP_mulss

UNSP_mulus = _ida_allins.UNSP_mulus

UNSP_muluu = _ida_allins.UNSP_muluu

UNSP_divs = _ida_allins.UNSP_divs

UNSP_divq = _ida_allins.UNSP_divq

UNSP_int1 = _ida_allins.UNSP_int1

UNSP_int2 = _ida_allins.UNSP_int2

UNSP_fir_mov = _ida_allins.UNSP_fir_mov

UNSP_fraction = _ida_allins.UNSP_fraction

UNSP_irq = _ida_allins.UNSP_irq

UNSP_secbank = _ida_allins.UNSP_secbank

UNSP_fiq = _ida_allins.UNSP_fiq

UNSP_irqnest = _ida_allins.UNSP_irqnest

UNSP_break = _ida_allins.UNSP_break

UNSP_asr = _ida_allins.UNSP_asr

UNSP_asror = _ida_allins.UNSP_asror

UNSP_lsl = _ida_allins.UNSP_lsl

UNSP_lslor = _ida_allins.UNSP_lslor

UNSP_lsr = _ida_allins.UNSP_lsr

UNSP_lsror = _ida_allins.UNSP_lsror

UNSP_rol = _ida_allins.UNSP_rol

UNSP_ror = _ida_allins.UNSP_ror

UNSP_tstb = _ida_allins.UNSP_tstb

UNSP_setb = _ida_allins.UNSP_setb

UNSP_clrb = _ida_allins.UNSP_clrb

UNSP_invb = _ida_allins.UNSP_invb

UNSP_last = _ida_allins.UNSP_last

DALVIK_UNUSED = _ida_allins.DALVIK_UNUSED

DALVIK_NOP = _ida_allins.DALVIK_NOP

DALVIK_MOVE = _ida_allins.DALVIK_MOVE

DALVIK_MOVE_FROM16 = _ida_allins.DALVIK_MOVE_FROM16

DALVIK_MOVE_16 = _ida_allins.DALVIK_MOVE_16

DALVIK_MOVE_WIDE = _ida_allins.DALVIK_MOVE_WIDE

DALVIK_MOVE_WIDE_FROM16 = _ida_allins.DALVIK_MOVE_WIDE_FROM16

DALVIK_MOVE_WIDE_16 = _ida_allins.DALVIK_MOVE_WIDE_16

DALVIK_MOVE_OBJECT = _ida_allins.DALVIK_MOVE_OBJECT

DALVIK_MOVE_OBJECT_FROM16 = _ida_allins.DALVIK_MOVE_OBJECT_FROM16

DALVIK_MOVE_OBJECT_16 = _ida_allins.DALVIK_MOVE_OBJECT_16

DALVIK_MOVE_RESULT = _ida_allins.DALVIK_MOVE_RESULT

DALVIK_MOVE_RESULT_WIDE = _ida_allins.DALVIK_MOVE_RESULT_WIDE

DALVIK_MOVE_RESULT_OBJECT = _ida_allins.DALVIK_MOVE_RESULT_OBJECT

DALVIK_MOVE_EXCEPTION = _ida_allins.DALVIK_MOVE_EXCEPTION

DALVIK_RETURN_VOID = _ida_allins.DALVIK_RETURN_VOID

DALVIK_RETURN = _ida_allins.DALVIK_RETURN

DALVIK_RETURN_WIDE = _ida_allins.DALVIK_RETURN_WIDE

DALVIK_RETURN_OBJECT = _ida_allins.DALVIK_RETURN_OBJECT

DALVIK_CONST_4 = _ida_allins.DALVIK_CONST_4

DALVIK_CONST_16 = _ida_allins.DALVIK_CONST_16

DALVIK_CONST = _ida_allins.DALVIK_CONST

DALVIK_CONST_HIGH16 = _ida_allins.DALVIK_CONST_HIGH16

DALVIK_CONST_WIDE_16 = _ida_allins.DALVIK_CONST_WIDE_16

DALVIK_CONST_WIDE_32 = _ida_allins.DALVIK_CONST_WIDE_32

DALVIK_CONST_WIDE = _ida_allins.DALVIK_CONST_WIDE

DALVIK_CONST_WIDE_HIGH16 = _ida_allins.DALVIK_CONST_WIDE_HIGH16

DALVIK_CONST_STRING = _ida_allins.DALVIK_CONST_STRING

DALVIK_CONST_STRING_JUMBO = _ida_allins.DALVIK_CONST_STRING_JUMBO

DALVIK_CONST_CLASS = _ida_allins.DALVIK_CONST_CLASS

DALVIK_MONITOR_ENTER = _ida_allins.DALVIK_MONITOR_ENTER

DALVIK_MONITOR_EXIT = _ida_allins.DALVIK_MONITOR_EXIT

DALVIK_CHECK_CAST = _ida_allins.DALVIK_CHECK_CAST

DALVIK_INSTANCE_OF = _ida_allins.DALVIK_INSTANCE_OF

DALVIK_ARRAY_LENGTH = _ida_allins.DALVIK_ARRAY_LENGTH

DALVIK_NEW_INSTANCE = _ida_allins.DALVIK_NEW_INSTANCE

DALVIK_NEW_ARRAY = _ida_allins.DALVIK_NEW_ARRAY

DALVIK_FILLED_NEW_ARRAY = _ida_allins.DALVIK_FILLED_NEW_ARRAY

DALVIK_FILLED_NEW_ARRAY_RANGE = _ida_allins.DALVIK_FILLED_NEW_ARRAY_RANGE

DALVIK_FILL_ARRAY_DATA = _ida_allins.DALVIK_FILL_ARRAY_DATA

DALVIK_THROW = _ida_allins.DALVIK_THROW

DALVIK_GOTO = _ida_allins.DALVIK_GOTO

DALVIK_GOTO_16 = _ida_allins.DALVIK_GOTO_16

DALVIK_GOTO_32 = _ida_allins.DALVIK_GOTO_32

DALVIK_PACKED_SWITCH = _ida_allins.DALVIK_PACKED_SWITCH

DALVIK_SPARSE_SWITCH = _ida_allins.DALVIK_SPARSE_SWITCH

DALVIK_CMPL_FLOAT = _ida_allins.DALVIK_CMPL_FLOAT

DALVIK_CMPG_FLOAT = _ida_allins.DALVIK_CMPG_FLOAT

DALVIK_CMPL_DOUBLE = _ida_allins.DALVIK_CMPL_DOUBLE

DALVIK_CMPG_DOUBLE = _ida_allins.DALVIK_CMPG_DOUBLE

DALVIK_CMP_LONG = _ida_allins.DALVIK_CMP_LONG

DALVIK_IF_EQ = _ida_allins.DALVIK_IF_EQ

DALVIK_IF_NE = _ida_allins.DALVIK_IF_NE

DALVIK_IF_LT = _ida_allins.DALVIK_IF_LT

DALVIK_IF_GE = _ida_allins.DALVIK_IF_GE

DALVIK_IF_GT = _ida_allins.DALVIK_IF_GT

DALVIK_IF_LE = _ida_allins.DALVIK_IF_LE

DALVIK_IF_EQZ = _ida_allins.DALVIK_IF_EQZ

DALVIK_IF_NEZ = _ida_allins.DALVIK_IF_NEZ

DALVIK_IF_LTZ = _ida_allins.DALVIK_IF_LTZ

DALVIK_IF_GEZ = _ida_allins.DALVIK_IF_GEZ

DALVIK_IF_GTZ = _ida_allins.DALVIK_IF_GTZ

DALVIK_IF_LEZ = _ida_allins.DALVIK_IF_LEZ

DALVIK_AGET = _ida_allins.DALVIK_AGET

DALVIK_AGET_WIDE = _ida_allins.DALVIK_AGET_WIDE

DALVIK_AGET_OBJECT = _ida_allins.DALVIK_AGET_OBJECT

DALVIK_AGET_BOOLEAN = _ida_allins.DALVIK_AGET_BOOLEAN

DALVIK_AGET_BYTE = _ida_allins.DALVIK_AGET_BYTE

DALVIK_AGET_CHAR = _ida_allins.DALVIK_AGET_CHAR

DALVIK_AGET_SHORT = _ida_allins.DALVIK_AGET_SHORT

DALVIK_APUT = _ida_allins.DALVIK_APUT

DALVIK_APUT_WIDE = _ida_allins.DALVIK_APUT_WIDE

DALVIK_APUT_OBJECT = _ida_allins.DALVIK_APUT_OBJECT

DALVIK_APUT_BOOLEAN = _ida_allins.DALVIK_APUT_BOOLEAN

DALVIK_APUT_BYTE = _ida_allins.DALVIK_APUT_BYTE

DALVIK_APUT_CHAR = _ida_allins.DALVIK_APUT_CHAR

DALVIK_APUT_SHORT = _ida_allins.DALVIK_APUT_SHORT

DALVIK_IGET = _ida_allins.DALVIK_IGET

DALVIK_IGET_WIDE = _ida_allins.DALVIK_IGET_WIDE

DALVIK_IGET_OBJECT = _ida_allins.DALVIK_IGET_OBJECT

DALVIK_IGET_BOOLEAN = _ida_allins.DALVIK_IGET_BOOLEAN

DALVIK_IGET_BYTE = _ida_allins.DALVIK_IGET_BYTE

DALVIK_IGET_CHAR = _ida_allins.DALVIK_IGET_CHAR

DALVIK_IGET_SHORT = _ida_allins.DALVIK_IGET_SHORT

DALVIK_IPUT = _ida_allins.DALVIK_IPUT

DALVIK_IPUT_WIDE = _ida_allins.DALVIK_IPUT_WIDE

DALVIK_IPUT_OBJECT = _ida_allins.DALVIK_IPUT_OBJECT

DALVIK_IPUT_BOOLEAN = _ida_allins.DALVIK_IPUT_BOOLEAN

DALVIK_IPUT_BYTE = _ida_allins.DALVIK_IPUT_BYTE

DALVIK_IPUT_CHAR = _ida_allins.DALVIK_IPUT_CHAR

DALVIK_IPUT_SHORT = _ida_allins.DALVIK_IPUT_SHORT

DALVIK_SGET = _ida_allins.DALVIK_SGET

DALVIK_SGET_WIDE = _ida_allins.DALVIK_SGET_WIDE

DALVIK_SGET_OBJECT = _ida_allins.DALVIK_SGET_OBJECT

DALVIK_SGET_BOOLEAN = _ida_allins.DALVIK_SGET_BOOLEAN

DALVIK_SGET_BYTE = _ida_allins.DALVIK_SGET_BYTE

DALVIK_SGET_CHAR = _ida_allins.DALVIK_SGET_CHAR

DALVIK_SGET_SHORT = _ida_allins.DALVIK_SGET_SHORT

DALVIK_SPUT = _ida_allins.DALVIK_SPUT

DALVIK_SPUT_WIDE = _ida_allins.DALVIK_SPUT_WIDE

DALVIK_SPUT_OBJECT = _ida_allins.DALVIK_SPUT_OBJECT

DALVIK_SPUT_BOOLEAN = _ida_allins.DALVIK_SPUT_BOOLEAN

DALVIK_SPUT_BYTE = _ida_allins.DALVIK_SPUT_BYTE

DALVIK_SPUT_CHAR = _ida_allins.DALVIK_SPUT_CHAR

DALVIK_SPUT_SHORT = _ida_allins.DALVIK_SPUT_SHORT

DALVIK_INVOKE_VIRTUAL = _ida_allins.DALVIK_INVOKE_VIRTUAL

DALVIK_INVOKE_SUPER = _ida_allins.DALVIK_INVOKE_SUPER

DALVIK_INVOKE_DIRECT = _ida_allins.DALVIK_INVOKE_DIRECT

DALVIK_INVOKE_STATIC = _ida_allins.DALVIK_INVOKE_STATIC

DALVIK_INVOKE_INTERFACE = _ida_allins.DALVIK_INVOKE_INTERFACE

DALVIK_INVOKE_VIRTUAL_RANGE = _ida_allins.DALVIK_INVOKE_VIRTUAL_RANGE

DALVIK_INVOKE_SUPER_RANGE = _ida_allins.DALVIK_INVOKE_SUPER_RANGE

DALVIK_INVOKE_DIRECT_RANGE = _ida_allins.DALVIK_INVOKE_DIRECT_RANGE

DALVIK_INVOKE_STATIC_RANGE = _ida_allins.DALVIK_INVOKE_STATIC_RANGE

DALVIK_INVOKE_INTERFACE_RANGE = _ida_allins.DALVIK_INVOKE_INTERFACE_RANGE

DALVIK_NEG_INT = _ida_allins.DALVIK_NEG_INT

DALVIK_NOT_INT = _ida_allins.DALVIK_NOT_INT

DALVIK_NEG_LONG = _ida_allins.DALVIK_NEG_LONG

DALVIK_NOT_LONG = _ida_allins.DALVIK_NOT_LONG

DALVIK_NEG_FLOAT = _ida_allins.DALVIK_NEG_FLOAT

DALVIK_NEG_DOUBLE = _ida_allins.DALVIK_NEG_DOUBLE

DALVIK_INT_TO_LONG = _ida_allins.DALVIK_INT_TO_LONG

DALVIK_INT_TO_FLOAT = _ida_allins.DALVIK_INT_TO_FLOAT

DALVIK_INT_TO_DOUBLE = _ida_allins.DALVIK_INT_TO_DOUBLE

DALVIK_LONG_TO_INT = _ida_allins.DALVIK_LONG_TO_INT

DALVIK_LONG_TO_FLOAT = _ida_allins.DALVIK_LONG_TO_FLOAT

DALVIK_LONG_TO_DOUBLE = _ida_allins.DALVIK_LONG_TO_DOUBLE

DALVIK_FLOAT_TO_INT = _ida_allins.DALVIK_FLOAT_TO_INT

DALVIK_FLOAT_TO_LONG = _ida_allins.DALVIK_FLOAT_TO_LONG

DALVIK_FLOAT_TO_DOUBLE = _ida_allins.DALVIK_FLOAT_TO_DOUBLE

DALVIK_DOUBLE_TO_INT = _ida_allins.DALVIK_DOUBLE_TO_INT

DALVIK_DOUBLE_TO_LONG = _ida_allins.DALVIK_DOUBLE_TO_LONG

DALVIK_DOUBLE_TO_FLOAT = _ida_allins.DALVIK_DOUBLE_TO_FLOAT

DALVIK_INT_TO_BYTE = _ida_allins.DALVIK_INT_TO_BYTE

DALVIK_INT_TO_CHAR = _ida_allins.DALVIK_INT_TO_CHAR

DALVIK_INT_TO_SHORT = _ida_allins.DALVIK_INT_TO_SHORT

DALVIK_ADD_INT = _ida_allins.DALVIK_ADD_INT

DALVIK_SUB_INT = _ida_allins.DALVIK_SUB_INT

DALVIK_MUL_INT = _ida_allins.DALVIK_MUL_INT

DALVIK_DIV_INT = _ida_allins.DALVIK_DIV_INT

DALVIK_REM_INT = _ida_allins.DALVIK_REM_INT

DALVIK_AND_INT = _ida_allins.DALVIK_AND_INT

DALVIK_OR_INT = _ida_allins.DALVIK_OR_INT

DALVIK_XOR_INT = _ida_allins.DALVIK_XOR_INT

DALVIK_SHL_INT = _ida_allins.DALVIK_SHL_INT

DALVIK_SHR_INT = _ida_allins.DALVIK_SHR_INT

DALVIK_USHR_INT = _ida_allins.DALVIK_USHR_INT

DALVIK_ADD_LONG = _ida_allins.DALVIK_ADD_LONG

DALVIK_SUB_LONG = _ida_allins.DALVIK_SUB_LONG

DALVIK_MUL_LONG = _ida_allins.DALVIK_MUL_LONG

DALVIK_DIV_LONG = _ida_allins.DALVIK_DIV_LONG

DALVIK_REM_LONG = _ida_allins.DALVIK_REM_LONG

DALVIK_AND_LONG = _ida_allins.DALVIK_AND_LONG

DALVIK_OR_LONG = _ida_allins.DALVIK_OR_LONG

DALVIK_XOR_LONG = _ida_allins.DALVIK_XOR_LONG

DALVIK_SHL_LONG = _ida_allins.DALVIK_SHL_LONG

DALVIK_SHR_LONG = _ida_allins.DALVIK_SHR_LONG

DALVIK_USHR_LONG = _ida_allins.DALVIK_USHR_LONG

DALVIK_ADD_FLOAT = _ida_allins.DALVIK_ADD_FLOAT

DALVIK_SUB_FLOAT = _ida_allins.DALVIK_SUB_FLOAT

DALVIK_MUL_FLOAT = _ida_allins.DALVIK_MUL_FLOAT

DALVIK_DIV_FLOAT = _ida_allins.DALVIK_DIV_FLOAT

DALVIK_REM_FLOAT = _ida_allins.DALVIK_REM_FLOAT

DALVIK_ADD_DOUBLE = _ida_allins.DALVIK_ADD_DOUBLE

DALVIK_SUB_DOUBLE = _ida_allins.DALVIK_SUB_DOUBLE

DALVIK_MUL_DOUBLE = _ida_allins.DALVIK_MUL_DOUBLE

DALVIK_DIV_DOUBLE = _ida_allins.DALVIK_DIV_DOUBLE

DALVIK_REM_DOUBLE = _ida_allins.DALVIK_REM_DOUBLE

DALVIK_ADD_INT_2ADDR = _ida_allins.DALVIK_ADD_INT_2ADDR

DALVIK_SUB_INT_2ADDR = _ida_allins.DALVIK_SUB_INT_2ADDR

DALVIK_MUL_INT_2ADDR = _ida_allins.DALVIK_MUL_INT_2ADDR

DALVIK_DIV_INT_2ADDR = _ida_allins.DALVIK_DIV_INT_2ADDR

DALVIK_REM_INT_2ADDR = _ida_allins.DALVIK_REM_INT_2ADDR

DALVIK_AND_INT_2ADDR = _ida_allins.DALVIK_AND_INT_2ADDR

DALVIK_OR_INT_2ADDR = _ida_allins.DALVIK_OR_INT_2ADDR

DALVIK_XOR_INT_2ADDR = _ida_allins.DALVIK_XOR_INT_2ADDR

DALVIK_SHL_INT_2ADDR = _ida_allins.DALVIK_SHL_INT_2ADDR

DALVIK_SHR_INT_2ADDR = _ida_allins.DALVIK_SHR_INT_2ADDR

DALVIK_USHR_INT_2ADDR = _ida_allins.DALVIK_USHR_INT_2ADDR

DALVIK_ADD_LONG_2ADDR = _ida_allins.DALVIK_ADD_LONG_2ADDR

DALVIK_SUB_LONG_2ADDR = _ida_allins.DALVIK_SUB_LONG_2ADDR

DALVIK_MUL_LONG_2ADDR = _ida_allins.DALVIK_MUL_LONG_2ADDR

DALVIK_DIV_LONG_2ADDR = _ida_allins.DALVIK_DIV_LONG_2ADDR

DALVIK_REM_LONG_2ADDR = _ida_allins.DALVIK_REM_LONG_2ADDR

DALVIK_AND_LONG_2ADDR = _ida_allins.DALVIK_AND_LONG_2ADDR

DALVIK_OR_LONG_2ADDR = _ida_allins.DALVIK_OR_LONG_2ADDR

DALVIK_XOR_LONG_2ADDR = _ida_allins.DALVIK_XOR_LONG_2ADDR

DALVIK_SHL_LONG_2ADDR = _ida_allins.DALVIK_SHL_LONG_2ADDR

DALVIK_SHR_LONG_2ADDR = _ida_allins.DALVIK_SHR_LONG_2ADDR

DALVIK_USHR_LONG_2ADDR = _ida_allins.DALVIK_USHR_LONG_2ADDR

DALVIK_ADD_FLOAT_2ADDR = _ida_allins.DALVIK_ADD_FLOAT_2ADDR

DALVIK_SUB_FLOAT_2ADDR = _ida_allins.DALVIK_SUB_FLOAT_2ADDR

DALVIK_MUL_FLOAT_2ADDR = _ida_allins.DALVIK_MUL_FLOAT_2ADDR

DALVIK_DIV_FLOAT_2ADDR = _ida_allins.DALVIK_DIV_FLOAT_2ADDR

DALVIK_REM_FLOAT_2ADDR = _ida_allins.DALVIK_REM_FLOAT_2ADDR

DALVIK_ADD_DOUBLE_2ADDR = _ida_allins.DALVIK_ADD_DOUBLE_2ADDR

DALVIK_SUB_DOUBLE_2ADDR = _ida_allins.DALVIK_SUB_DOUBLE_2ADDR

DALVIK_MUL_DOUBLE_2ADDR = _ida_allins.DALVIK_MUL_DOUBLE_2ADDR

DALVIK_DIV_DOUBLE_2ADDR = _ida_allins.DALVIK_DIV_DOUBLE_2ADDR

DALVIK_REM_DOUBLE_2ADDR = _ida_allins.DALVIK_REM_DOUBLE_2ADDR

DALVIK_ADD_INT_LIT16 = _ida_allins.DALVIK_ADD_INT_LIT16

DALVIK_RSUB_INT = _ida_allins.DALVIK_RSUB_INT

DALVIK_MUL_INT_LIT16 = _ida_allins.DALVIK_MUL_INT_LIT16

DALVIK_DIV_INT_LIT16 = _ida_allins.DALVIK_DIV_INT_LIT16

DALVIK_REM_INT_LIT16 = _ida_allins.DALVIK_REM_INT_LIT16

DALVIK_AND_INT_LIT16 = _ida_allins.DALVIK_AND_INT_LIT16

DALVIK_OR_INT_LIT16 = _ida_allins.DALVIK_OR_INT_LIT16

DALVIK_XOR_INT_LIT16 = _ida_allins.DALVIK_XOR_INT_LIT16

DALVIK_ADD_INT_LIT8 = _ida_allins.DALVIK_ADD_INT_LIT8

DALVIK_RSUB_INT_LIT8 = _ida_allins.DALVIK_RSUB_INT_LIT8

DALVIK_MUL_INT_LIT8 = _ida_allins.DALVIK_MUL_INT_LIT8

DALVIK_DIV_INT_LIT8 = _ida_allins.DALVIK_DIV_INT_LIT8

DALVIK_REM_INT_LIT8 = _ida_allins.DALVIK_REM_INT_LIT8

DALVIK_AND_INT_LIT8 = _ida_allins.DALVIK_AND_INT_LIT8

DALVIK_OR_INT_LIT8 = _ida_allins.DALVIK_OR_INT_LIT8

DALVIK_XOR_INT_LIT8 = _ida_allins.DALVIK_XOR_INT_LIT8

DALVIK_SHL_INT_LIT8 = _ida_allins.DALVIK_SHL_INT_LIT8

DALVIK_SHR_INT_LIT8 = _ida_allins.DALVIK_SHR_INT_LIT8

DALVIK_USHR_INT_LIT8 = _ida_allins.DALVIK_USHR_INT_LIT8

DALVIK_IGET_VOLATILE = _ida_allins.DALVIK_IGET_VOLATILE

DALVIK_IPUT_VOLATILE = _ida_allins.DALVIK_IPUT_VOLATILE

DALVIK_SGET_VOLATILE = _ida_allins.DALVIK_SGET_VOLATILE

DALVIK_SPUT_VOLATILE = _ida_allins.DALVIK_SPUT_VOLATILE

DALVIK_IGET_OBJECT_VOLATILE = _ida_allins.DALVIK_IGET_OBJECT_VOLATILE

DALVIK_IGET_WIDE_VOLATILE = _ida_allins.DALVIK_IGET_WIDE_VOLATILE

DALVIK_IPUT_WIDE_VOLATILE = _ida_allins.DALVIK_IPUT_WIDE_VOLATILE

DALVIK_SGET_WIDE_VOLATILE = _ida_allins.DALVIK_SGET_WIDE_VOLATILE

DALVIK_SPUT_WIDE_VOLATILE = _ida_allins.DALVIK_SPUT_WIDE_VOLATILE

DALVIK_BREAKPOINT = _ida_allins.DALVIK_BREAKPOINT

DALVIK_THROW_VERIFICATION_ERROR = _ida_allins.DALVIK_THROW_VERIFICATION_ERROR

DALVIK_EXECUTE_INLINE = _ida_allins.DALVIK_EXECUTE_INLINE

DALVIK_EXECUTE_INLINE_RANGE = _ida_allins.DALVIK_EXECUTE_INLINE_RANGE

DALVIK_INVOKE_DIRECT_EMPTY = _ida_allins.DALVIK_INVOKE_DIRECT_EMPTY

DALVIK_RETURN_VOID_BARRIER = _ida_allins.DALVIK_RETURN_VOID_BARRIER

DALVIK_IGET_QUICK = _ida_allins.DALVIK_IGET_QUICK

DALVIK_IGET_WIDE_QUICK = _ida_allins.DALVIK_IGET_WIDE_QUICK

DALVIK_IGET_OBJECT_QUICK = _ida_allins.DALVIK_IGET_OBJECT_QUICK

DALVIK_IPUT_QUICK = _ida_allins.DALVIK_IPUT_QUICK

DALVIK_IPUT_WIDE_QUICK = _ida_allins.DALVIK_IPUT_WIDE_QUICK

DALVIK_IPUT_OBJECT_QUICK = _ida_allins.DALVIK_IPUT_OBJECT_QUICK

DALVIK_INVOKE_VIRTUAL_QUICK = _ida_allins.DALVIK_INVOKE_VIRTUAL_QUICK

DALVIK_INVOKE_VIRTUAL_QUICK_RANGE = _ida_allins.DALVIK_INVOKE_VIRTUAL_QUICK_RANGE

DALVIK_INVOKE_SUPER_QUICK = _ida_allins.DALVIK_INVOKE_SUPER_QUICK

DALVIK_INVOKE_SUPER_QUICK_RANGE = _ida_allins.DALVIK_INVOKE_SUPER_QUICK_RANGE

DALVIK_IPUT_OBJECT_VOLATILE = _ida_allins.DALVIK_IPUT_OBJECT_VOLATILE

DALVIK_SGET_OBJECT_VOLATILE = _ida_allins.DALVIK_SGET_OBJECT_VOLATILE

DALVIK_SPUT_OBJECT_VOLATILE = _ida_allins.DALVIK_SPUT_OBJECT_VOLATILE

DALVIK_INVOKE_POLYMORPHIC = _ida_allins.DALVIK_INVOKE_POLYMORPHIC

DALVIK_INVOKE_POLYMORPHIC_RANGE = _ida_allins.DALVIK_INVOKE_POLYMORPHIC_RANGE

DALVIK_INVOKE_CUSTOM = _ida_allins.DALVIK_INVOKE_CUSTOM

DALVIK_INVOKE_CUSTOM_RANGE = _ida_allins.DALVIK_INVOKE_CUSTOM_RANGE

DALVIK_LAST = _ida_allins.DALVIK_LAST

s39_null = _ida_allins.s39_null

s39_a = _ida_allins.s39_a

s39_ad = _ida_allins.s39_ad

s39_adb = _ida_allins.s39_adb

s39_adbr = _ida_allins.s39_adbr

s39_adr = _ida_allins.s39_adr

s39_adtr = _ida_allins.s39_adtr

s39_adtra = _ida_allins.s39_adtra

s39_ae = _ida_allins.s39_ae

s39_aeb = _ida_allins.s39_aeb

s39_aebr = _ida_allins.s39_aebr

s39_aer = _ida_allins.s39_aer

s39_afi = _ida_allins.s39_afi

s39_ag = _ida_allins.s39_ag

s39_agf = _ida_allins.s39_agf

s39_agfi = _ida_allins.s39_agfi

s39_agfr = _ida_allins.s39_agfr

s39_agh = _ida_allins.s39_agh

s39_aghi = _ida_allins.s39_aghi

s39_aghik = _ida_allins.s39_aghik

s39_agr = _ida_allins.s39_agr

s39_agrk = _ida_allins.s39_agrk

s39_agsi = _ida_allins.s39_agsi

s39_ah = _ida_allins.s39_ah

s39_ahhhr = _ida_allins.s39_ahhhr

s39_ahhlr = _ida_allins.s39_ahhlr

s39_ahi = _ida_allins.s39_ahi

s39_ahik = _ida_allins.s39_ahik

s39_ahy = _ida_allins.s39_ahy

s39_aih = _ida_allins.s39_aih

s39_al = _ida_allins.s39_al

s39_alc = _ida_allins.s39_alc

s39_alcg = _ida_allins.s39_alcg

s39_alcgr = _ida_allins.s39_alcgr

s39_alcr = _ida_allins.s39_alcr

s39_alfi = _ida_allins.s39_alfi

s39_alg = _ida_allins.s39_alg

s39_algf = _ida_allins.s39_algf

s39_algfi = _ida_allins.s39_algfi

s39_algfr = _ida_allins.s39_algfr

s39_alghsik = _ida_allins.s39_alghsik

s39_algr = _ida_allins.s39_algr

s39_algrk = _ida_allins.s39_algrk

s39_algsi = _ida_allins.s39_algsi

s39_alhhhr = _ida_allins.s39_alhhhr

s39_alhhlr = _ida_allins.s39_alhhlr

s39_alhsik = _ida_allins.s39_alhsik

s39_alr = _ida_allins.s39_alr

s39_alrk = _ida_allins.s39_alrk

s39_alsi = _ida_allins.s39_alsi

s39_alsih = _ida_allins.s39_alsih

s39_alsihn = _ida_allins.s39_alsihn

s39_aly = _ida_allins.s39_aly

s39_ap = _ida_allins.s39_ap

s39_ar = _ida_allins.s39_ar

s39_ark = _ida_allins.s39_ark

s39_asi = _ida_allins.s39_asi

s39_au = _ida_allins.s39_au

s39_aur = _ida_allins.s39_aur

s39_aw = _ida_allins.s39_aw

s39_awr = _ida_allins.s39_awr

s39_axbr = _ida_allins.s39_axbr

s39_axr = _ida_allins.s39_axr

s39_axtr = _ida_allins.s39_axtr

s39_axtra = _ida_allins.s39_axtra

s39_ay = _ida_allins.s39_ay

s39_b = _ida_allins.s39_b

s39_bo = _ida_allins.s39_bo

s39_bh = _ida_allins.s39_bh

s39_bnle = _ida_allins.s39_bnle

s39_bl = _ida_allins.s39_bl

s39_bnhe = _ida_allins.s39_bnhe

s39_blh = _ida_allins.s39_blh

s39_bne = _ida_allins.s39_bne

s39_be = _ida_allins.s39_be

s39_bnlh = _ida_allins.s39_bnlh

s39_bhe = _ida_allins.s39_bhe

s39_bnl = _ida_allins.s39_bnl

s39_ble = _ida_allins.s39_ble

s39_bnh = _ida_allins.s39_bnh

s39_bno = _ida_allins.s39_bno

s39_bor = _ida_allins.s39_bor

s39_bhr = _ida_allins.s39_bhr

s39_bnler = _ida_allins.s39_bnler

s39_blr = _ida_allins.s39_blr

s39_bnher = _ida_allins.s39_bnher

s39_blhr = _ida_allins.s39_blhr

s39_bner = _ida_allins.s39_bner

s39_ber = _ida_allins.s39_ber

s39_bnlhr = _ida_allins.s39_bnlhr

s39_bher = _ida_allins.s39_bher

s39_bnlr = _ida_allins.s39_bnlr

s39_bler = _ida_allins.s39_bler

s39_bnhr = _ida_allins.s39_bnhr

s39_bnor = _ida_allins.s39_bnor

s39_bakr = _ida_allins.s39_bakr

s39_bal = _ida_allins.s39_bal

s39_balr = _ida_allins.s39_balr

s39_bas = _ida_allins.s39_bas

s39_basr = _ida_allins.s39_basr

s39_bassm = _ida_allins.s39_bassm

s39_bc = _ida_allins.s39_bc

s39_bcr = _ida_allins.s39_bcr

s39_bct = _ida_allins.s39_bct

s39_bctg = _ida_allins.s39_bctg

s39_bctgr = _ida_allins.s39_bctgr

s39_bctr = _ida_allins.s39_bctr

s39_bi = _ida_allins.s39_bi

s39_bio = _ida_allins.s39_bio

s39_bih = _ida_allins.s39_bih

s39_binle = _ida_allins.s39_binle

s39_bil = _ida_allins.s39_bil

s39_binhe = _ida_allins.s39_binhe

s39_bilh = _ida_allins.s39_bilh

s39_bine = _ida_allins.s39_bine

s39_bie = _ida_allins.s39_bie

s39_binlh = _ida_allins.s39_binlh

s39_bihe = _ida_allins.s39_bihe

s39_binl = _ida_allins.s39_binl

s39_bile = _ida_allins.s39_bile

s39_binh = _ida_allins.s39_binh

s39_bino = _ida_allins.s39_bino

s39_bic = _ida_allins.s39_bic

s39_bpp = _ida_allins.s39_bpp

s39_bprp = _ida_allins.s39_bprp

s39_br = _ida_allins.s39_br

s39_bras = _ida_allins.s39_bras

s39_brasl = _ida_allins.s39_brasl

s39_brc = _ida_allins.s39_brc

s39_brcl = _ida_allins.s39_brcl

s39_brct = _ida_allins.s39_brct

s39_brctg = _ida_allins.s39_brctg

s39_brcth = _ida_allins.s39_brcth

s39_brxh = _ida_allins.s39_brxh

s39_brxhg = _ida_allins.s39_brxhg

s39_brxle = _ida_allins.s39_brxle

s39_brxlg = _ida_allins.s39_brxlg

s39_bsa = _ida_allins.s39_bsa

s39_bsg = _ida_allins.s39_bsg

s39_bsm = _ida_allins.s39_bsm

s39_bxh = _ida_allins.s39_bxh

s39_bxhg = _ida_allins.s39_bxhg

s39_bxle = _ida_allins.s39_bxle

s39_bxleg = _ida_allins.s39_bxleg

s39_c = _ida_allins.s39_c

s39_cd = _ida_allins.s39_cd

s39_cdb = _ida_allins.s39_cdb

s39_cdbr = _ida_allins.s39_cdbr

s39_cdfbr = _ida_allins.s39_cdfbr

s39_cdfbra = _ida_allins.s39_cdfbra

s39_cdfr = _ida_allins.s39_cdfr

s39_cdftr = _ida_allins.s39_cdftr

s39_cdgbr = _ida_allins.s39_cdgbr

s39_cdgbra = _ida_allins.s39_cdgbra

s39_cdgr = _ida_allins.s39_cdgr

s39_cdgtr = _ida_allins.s39_cdgtr

s39_cdgtra = _ida_allins.s39_cdgtra

s39_cdlfbr = _ida_allins.s39_cdlfbr

s39_cdlftr = _ida_allins.s39_cdlftr

s39_cdlgbr = _ida_allins.s39_cdlgbr

s39_cdlgtr = _ida_allins.s39_cdlgtr

s39_cdpt = _ida_allins.s39_cdpt

s39_cdr = _ida_allins.s39_cdr

s39_cds = _ida_allins.s39_cds

s39_cdsg = _ida_allins.s39_cdsg

s39_cdstr = _ida_allins.s39_cdstr

s39_cdsy = _ida_allins.s39_cdsy

s39_cdtr = _ida_allins.s39_cdtr

s39_cdutr = _ida_allins.s39_cdutr

s39_cdzt = _ida_allins.s39_cdzt

s39_ce = _ida_allins.s39_ce

s39_ceb = _ida_allins.s39_ceb

s39_cebr = _ida_allins.s39_cebr

s39_cedtr = _ida_allins.s39_cedtr

s39_cefbr = _ida_allins.s39_cefbr

s39_cefbra = _ida_allins.s39_cefbra

s39_cefr = _ida_allins.s39_cefr

s39_cegbr = _ida_allins.s39_cegbr

s39_cegbra = _ida_allins.s39_cegbra

s39_cegr = _ida_allins.s39_cegr

s39_celfbr = _ida_allins.s39_celfbr

s39_celgbr = _ida_allins.s39_celgbr

s39_cer = _ida_allins.s39_cer

s39_cextr = _ida_allins.s39_cextr

s39_cfc = _ida_allins.s39_cfc

s39_cfdbr = _ida_allins.s39_cfdbr

s39_cfdbra = _ida_allins.s39_cfdbra

s39_cfdr = _ida_allins.s39_cfdr

s39_cfdtr = _ida_allins.s39_cfdtr

s39_cfebr = _ida_allins.s39_cfebr

s39_cfebra = _ida_allins.s39_cfebra

s39_cfer = _ida_allins.s39_cfer

s39_cfi = _ida_allins.s39_cfi

s39_cfxbr = _ida_allins.s39_cfxbr

s39_cfxbra = _ida_allins.s39_cfxbra

s39_cfxr = _ida_allins.s39_cfxr

s39_cfxtr = _ida_allins.s39_cfxtr

s39_cg = _ida_allins.s39_cg

s39_cgdbr = _ida_allins.s39_cgdbr

s39_cgdbra = _ida_allins.s39_cgdbra

s39_cgdr = _ida_allins.s39_cgdr

s39_cgdtr = _ida_allins.s39_cgdtr

s39_cgdtra = _ida_allins.s39_cgdtra

s39_cgebr = _ida_allins.s39_cgebr

s39_cgebra = _ida_allins.s39_cgebra

s39_cger = _ida_allins.s39_cger

s39_cgf = _ida_allins.s39_cgf

s39_cgfi = _ida_allins.s39_cgfi

s39_cgfr = _ida_allins.s39_cgfr

s39_cgfrl = _ida_allins.s39_cgfrl

s39_cgh = _ida_allins.s39_cgh

s39_cghi = _ida_allins.s39_cghi

s39_cghrl = _ida_allins.s39_cghrl

s39_cghsi = _ida_allins.s39_cghsi

s39_cgib = _ida_allins.s39_cgib

s39_cgibh = _ida_allins.s39_cgibh

s39_cgibnhe = _ida_allins.s39_cgibnhe

s39_cgiblh = _ida_allins.s39_cgiblh

s39_cgibnlh = _ida_allins.s39_cgibnlh

s39_cgibnl = _ida_allins.s39_cgibnl

s39_cgible = _ida_allins.s39_cgible

s39_cgij = _ida_allins.s39_cgij

s39_cgijh = _ida_allins.s39_cgijh

s39_cgijnhe = _ida_allins.s39_cgijnhe

s39_cgijlh = _ida_allins.s39_cgijlh

s39_cgijnlh = _ida_allins.s39_cgijnlh

s39_cgijnl = _ida_allins.s39_cgijnl

s39_cgijle = _ida_allins.s39_cgijle

s39_cgit = _ida_allins.s39_cgit

s39_cgith = _ida_allins.s39_cgith

s39_cgitnhe = _ida_allins.s39_cgitnhe

s39_cgitlh = _ida_allins.s39_cgitlh

s39_cgitnlh = _ida_allins.s39_cgitnlh

s39_cgitnl = _ida_allins.s39_cgitnl

s39_cgitle = _ida_allins.s39_cgitle

s39_cgr = _ida_allins.s39_cgr

s39_cgrb = _ida_allins.s39_cgrb

s39_cgrbh = _ida_allins.s39_cgrbh

s39_cgrbnhe = _ida_allins.s39_cgrbnhe

s39_cgrblh = _ida_allins.s39_cgrblh

s39_cgrbnlh = _ida_allins.s39_cgrbnlh

s39_cgrbnl = _ida_allins.s39_cgrbnl

s39_cgrble = _ida_allins.s39_cgrble

s39_cgrj = _ida_allins.s39_cgrj

s39_cgrjh = _ida_allins.s39_cgrjh

s39_cgrjnhe = _ida_allins.s39_cgrjnhe

s39_cgrjlh = _ida_allins.s39_cgrjlh

s39_cgrjnlh = _ida_allins.s39_cgrjnlh

s39_cgrjnl = _ida_allins.s39_cgrjnl

s39_cgrjle = _ida_allins.s39_cgrjle

s39_cgrl = _ida_allins.s39_cgrl

s39_cgrt = _ida_allins.s39_cgrt

s39_cgrth = _ida_allins.s39_cgrth

s39_cgrtnhe = _ida_allins.s39_cgrtnhe

s39_cgrtlh = _ida_allins.s39_cgrtlh

s39_cgrtnlh = _ida_allins.s39_cgrtnlh

s39_cgrtnl = _ida_allins.s39_cgrtnl

s39_cgrtle = _ida_allins.s39_cgrtle

s39_cgxbr = _ida_allins.s39_cgxbr

s39_cgxbra = _ida_allins.s39_cgxbra

s39_cgxr = _ida_allins.s39_cgxr

s39_cgxtr = _ida_allins.s39_cgxtr

s39_cgxtra = _ida_allins.s39_cgxtra

s39_ch = _ida_allins.s39_ch

s39_chf = _ida_allins.s39_chf

s39_chhr = _ida_allins.s39_chhr

s39_chhsi = _ida_allins.s39_chhsi

s39_chi = _ida_allins.s39_chi

s39_chlr = _ida_allins.s39_chlr

s39_chrl = _ida_allins.s39_chrl

s39_chsi = _ida_allins.s39_chsi

s39_chy = _ida_allins.s39_chy

s39_cib = _ida_allins.s39_cib

s39_cibh = _ida_allins.s39_cibh

s39_cibnhe = _ida_allins.s39_cibnhe

s39_ciblh = _ida_allins.s39_ciblh

s39_cibnlh = _ida_allins.s39_cibnlh

s39_cibnl = _ida_allins.s39_cibnl

s39_cible = _ida_allins.s39_cible

s39_cih = _ida_allins.s39_cih

s39_cij = _ida_allins.s39_cij

s39_cijh = _ida_allins.s39_cijh

s39_cijnhe = _ida_allins.s39_cijnhe

s39_cijlh = _ida_allins.s39_cijlh

s39_cijnlh = _ida_allins.s39_cijnlh

s39_cijnl = _ida_allins.s39_cijnl

s39_cijle = _ida_allins.s39_cijle

s39_cit = _ida_allins.s39_cit

s39_cith = _ida_allins.s39_cith

s39_citnhe = _ida_allins.s39_citnhe

s39_citlh = _ida_allins.s39_citlh

s39_citnlh = _ida_allins.s39_citnlh

s39_citnl = _ida_allins.s39_citnl

s39_citle = _ida_allins.s39_citle

s39_cksm = _ida_allins.s39_cksm

s39_cl = _ida_allins.s39_cl

s39_clc = _ida_allins.s39_clc

s39_clcl = _ida_allins.s39_clcl

s39_clcle = _ida_allins.s39_clcle

s39_clclu = _ida_allins.s39_clclu

s39_clfdbr = _ida_allins.s39_clfdbr

s39_clfdtr = _ida_allins.s39_clfdtr

s39_clfebr = _ida_allins.s39_clfebr

s39_clfhsi = _ida_allins.s39_clfhsi

s39_clfi = _ida_allins.s39_clfi

s39_clfit = _ida_allins.s39_clfit

s39_clfith = _ida_allins.s39_clfith

s39_clfitnhe = _ida_allins.s39_clfitnhe

s39_clfitlh = _ida_allins.s39_clfitlh

s39_clfitnlh = _ida_allins.s39_clfitnlh

s39_clfitnl = _ida_allins.s39_clfitnl

s39_clfitle = _ida_allins.s39_clfitle

s39_clfxbr = _ida_allins.s39_clfxbr

s39_clfxtr = _ida_allins.s39_clfxtr

s39_clg = _ida_allins.s39_clg

s39_clgdbr = _ida_allins.s39_clgdbr

s39_clgdtr = _ida_allins.s39_clgdtr

s39_clgebr = _ida_allins.s39_clgebr

s39_clgf = _ida_allins.s39_clgf

s39_clgfi = _ida_allins.s39_clgfi

s39_clgfr = _ida_allins.s39_clgfr

s39_clgfrl = _ida_allins.s39_clgfrl

s39_clghrl = _ida_allins.s39_clghrl

s39_clghsi = _ida_allins.s39_clghsi

s39_clgib = _ida_allins.s39_clgib

s39_clgibh = _ida_allins.s39_clgibh

s39_clgibnhe = _ida_allins.s39_clgibnhe

s39_clgiblh = _ida_allins.s39_clgiblh

s39_clgibnlh = _ida_allins.s39_clgibnlh

s39_clgibnl = _ida_allins.s39_clgibnl

s39_clgible = _ida_allins.s39_clgible

s39_clgij = _ida_allins.s39_clgij

s39_clgijh = _ida_allins.s39_clgijh

s39_clgijnhe = _ida_allins.s39_clgijnhe

s39_clgijlh = _ida_allins.s39_clgijlh

s39_clgijnlh = _ida_allins.s39_clgijnlh

s39_clgijnl = _ida_allins.s39_clgijnl

s39_clgijle = _ida_allins.s39_clgijle

s39_clgit = _ida_allins.s39_clgit

s39_clgith = _ida_allins.s39_clgith

s39_clgitnhe = _ida_allins.s39_clgitnhe

s39_clgitlh = _ida_allins.s39_clgitlh

s39_clgitnlh = _ida_allins.s39_clgitnlh

s39_clgitnl = _ida_allins.s39_clgitnl

s39_clgitle = _ida_allins.s39_clgitle

s39_clgr = _ida_allins.s39_clgr

s39_clgrb = _ida_allins.s39_clgrb

s39_clgrbh = _ida_allins.s39_clgrbh

s39_clgrbnhe = _ida_allins.s39_clgrbnhe

s39_clgrblh = _ida_allins.s39_clgrblh

s39_clgrbnlh = _ida_allins.s39_clgrbnlh

s39_clgrbnl = _ida_allins.s39_clgrbnl

s39_clgrble = _ida_allins.s39_clgrble

s39_clgrj = _ida_allins.s39_clgrj

s39_clgrjh = _ida_allins.s39_clgrjh

s39_clgrjnhe = _ida_allins.s39_clgrjnhe

s39_clgrjlh = _ida_allins.s39_clgrjlh

s39_clgrjnlh = _ida_allins.s39_clgrjnlh

s39_clgrjnl = _ida_allins.s39_clgrjnl

s39_clgrjle = _ida_allins.s39_clgrjle

s39_clgrl = _ida_allins.s39_clgrl

s39_clgrt = _ida_allins.s39_clgrt

s39_clgrth = _ida_allins.s39_clgrth

s39_clgrtnhe = _ida_allins.s39_clgrtnhe

s39_clgrtlh = _ida_allins.s39_clgrtlh

s39_clgrtnlh = _ida_allins.s39_clgrtnlh

s39_clgrtnl = _ida_allins.s39_clgrtnl

s39_clgrtle = _ida_allins.s39_clgrtle

s39_clgt = _ida_allins.s39_clgt

s39_clgth = _ida_allins.s39_clgth

s39_clgtnhe = _ida_allins.s39_clgtnhe

s39_clgtlh = _ida_allins.s39_clgtlh

s39_clgtnlh = _ida_allins.s39_clgtnlh

s39_clgtnl = _ida_allins.s39_clgtnl

s39_clgtle = _ida_allins.s39_clgtle

s39_clgxbr = _ida_allins.s39_clgxbr

s39_clgxtr = _ida_allins.s39_clgxtr

s39_clhf = _ida_allins.s39_clhf

s39_clhhr = _ida_allins.s39_clhhr

s39_clhhsi = _ida_allins.s39_clhhsi

s39_clhlr = _ida_allins.s39_clhlr

s39_clhrl = _ida_allins.s39_clhrl

s39_cli = _ida_allins.s39_cli

s39_clib = _ida_allins.s39_clib

s39_clibh = _ida_allins.s39_clibh

s39_clibnhe = _ida_allins.s39_clibnhe

s39_cliblh = _ida_allins.s39_cliblh

s39_clibnlh = _ida_allins.s39_clibnlh

s39_clibnl = _ida_allins.s39_clibnl

s39_clible = _ida_allins.s39_clible

s39_clih = _ida_allins.s39_clih

s39_clij = _ida_allins.s39_clij

s39_clijh = _ida_allins.s39_clijh

s39_clijnhe = _ida_allins.s39_clijnhe

s39_clijlh = _ida_allins.s39_clijlh

s39_clijnlh = _ida_allins.s39_clijnlh

s39_clijnl = _ida_allins.s39_clijnl

s39_clijle = _ida_allins.s39_clijle

s39_cliy = _ida_allins.s39_cliy

s39_clm = _ida_allins.s39_clm

s39_clmh = _ida_allins.s39_clmh

s39_clmy = _ida_allins.s39_clmy

s39_clr = _ida_allins.s39_clr

s39_clrb = _ida_allins.s39_clrb

s39_clrbh = _ida_allins.s39_clrbh

s39_clrbnhe = _ida_allins.s39_clrbnhe

s39_clrblh = _ida_allins.s39_clrblh

s39_clrbnlh = _ida_allins.s39_clrbnlh

s39_clrbnl = _ida_allins.s39_clrbnl

s39_clrble = _ida_allins.s39_clrble

s39_clrj = _ida_allins.s39_clrj

s39_clrjh = _ida_allins.s39_clrjh

s39_clrjnhe = _ida_allins.s39_clrjnhe

s39_clrjlh = _ida_allins.s39_clrjlh

s39_clrjnlh = _ida_allins.s39_clrjnlh

s39_clrjnl = _ida_allins.s39_clrjnl

s39_clrjle = _ida_allins.s39_clrjle

s39_clrl = _ida_allins.s39_clrl

s39_clrt = _ida_allins.s39_clrt

s39_clrth = _ida_allins.s39_clrth

s39_clrtnhe = _ida_allins.s39_clrtnhe

s39_clrtlh = _ida_allins.s39_clrtlh

s39_clrtnlh = _ida_allins.s39_clrtnlh

s39_clrtnl = _ida_allins.s39_clrtnl

s39_clrtle = _ida_allins.s39_clrtle

s39_clst = _ida_allins.s39_clst

s39_clt = _ida_allins.s39_clt

s39_clth = _ida_allins.s39_clth

s39_cltnhe = _ida_allins.s39_cltnhe

s39_cltlh = _ida_allins.s39_cltlh

s39_cltnlh = _ida_allins.s39_cltnlh

s39_cltnl = _ida_allins.s39_cltnl

s39_cltle = _ida_allins.s39_cltle

s39_cly = _ida_allins.s39_cly

s39_cmpsc = _ida_allins.s39_cmpsc

s39_cp = _ida_allins.s39_cp

s39_cpdt = _ida_allins.s39_cpdt

s39_cpsdr = _ida_allins.s39_cpsdr

s39_cpxt = _ida_allins.s39_cpxt

s39_cpya = _ida_allins.s39_cpya

s39_cr = _ida_allins.s39_cr

s39_crb = _ida_allins.s39_crb

s39_crbh = _ida_allins.s39_crbh

s39_crbnhe = _ida_allins.s39_crbnhe

s39_crblh = _ida_allins.s39_crblh

s39_crbnlh = _ida_allins.s39_crbnlh

s39_crbnl = _ida_allins.s39_crbnl

s39_crble = _ida_allins.s39_crble

s39_crdte = _ida_allins.s39_crdte

s39_crj = _ida_allins.s39_crj

s39_crjh = _ida_allins.s39_crjh

s39_crjnhe = _ida_allins.s39_crjnhe

s39_crjlh = _ida_allins.s39_crjlh

s39_crjnlh = _ida_allins.s39_crjnlh

s39_crjnl = _ida_allins.s39_crjnl

s39_crjle = _ida_allins.s39_crjle

s39_crl = _ida_allins.s39_crl

s39_crt = _ida_allins.s39_crt

s39_crth = _ida_allins.s39_crth

s39_crtnhe = _ida_allins.s39_crtnhe

s39_crtlh = _ida_allins.s39_crtlh

s39_crtnlh = _ida_allins.s39_crtnlh

s39_crtnl = _ida_allins.s39_crtnl

s39_crtle = _ida_allins.s39_crtle

s39_cs = _ida_allins.s39_cs

s39_csch = _ida_allins.s39_csch

s39_csdtr = _ida_allins.s39_csdtr

s39_csg = _ida_allins.s39_csg

s39_csp = _ida_allins.s39_csp

s39_cspg = _ida_allins.s39_cspg

s39_csst = _ida_allins.s39_csst

s39_csxtr = _ida_allins.s39_csxtr

s39_csy = _ida_allins.s39_csy

s39_cu12 = _ida_allins.s39_cu12

s39_cu14 = _ida_allins.s39_cu14

s39_cu21 = _ida_allins.s39_cu21

s39_cu24 = _ida_allins.s39_cu24

s39_cu41 = _ida_allins.s39_cu41

s39_cu42 = _ida_allins.s39_cu42

s39_cudtr = _ida_allins.s39_cudtr

s39_cuse = _ida_allins.s39_cuse

s39_cutfu = _ida_allins.s39_cutfu

s39_cuutf = _ida_allins.s39_cuutf

s39_cuxtr = _ida_allins.s39_cuxtr

s39_cvb = _ida_allins.s39_cvb

s39_cvbg = _ida_allins.s39_cvbg

s39_cvby = _ida_allins.s39_cvby

s39_cvd = _ida_allins.s39_cvd

s39_cvdg = _ida_allins.s39_cvdg

s39_cvdy = _ida_allins.s39_cvdy

s39_cxbr = _ida_allins.s39_cxbr

s39_cxfbr = _ida_allins.s39_cxfbr

s39_cxfbra = _ida_allins.s39_cxfbra

s39_cxfr = _ida_allins.s39_cxfr

s39_cxftr = _ida_allins.s39_cxftr

s39_cxgbr = _ida_allins.s39_cxgbr

s39_cxgbra = _ida_allins.s39_cxgbra

s39_cxgr = _ida_allins.s39_cxgr

s39_cxgtr = _ida_allins.s39_cxgtr

s39_cxgtra = _ida_allins.s39_cxgtra

s39_cxlfbr = _ida_allins.s39_cxlfbr

s39_cxlftr = _ida_allins.s39_cxlftr

s39_cxlgbr = _ida_allins.s39_cxlgbr

s39_cxlgtr = _ida_allins.s39_cxlgtr

s39_cxpt = _ida_allins.s39_cxpt

s39_cxr = _ida_allins.s39_cxr

s39_cxstr = _ida_allins.s39_cxstr

s39_cxtr = _ida_allins.s39_cxtr

s39_cxutr = _ida_allins.s39_cxutr

s39_cxzt = _ida_allins.s39_cxzt

s39_cy = _ida_allins.s39_cy

s39_czdt = _ida_allins.s39_czdt

s39_czxt = _ida_allins.s39_czxt

s39_d = _ida_allins.s39_d

s39_dd = _ida_allins.s39_dd

s39_ddb = _ida_allins.s39_ddb

s39_ddbr = _ida_allins.s39_ddbr

s39_ddr = _ida_allins.s39_ddr

s39_ddtr = _ida_allins.s39_ddtr

s39_ddtra = _ida_allins.s39_ddtra

s39_de = _ida_allins.s39_de

s39_deb = _ida_allins.s39_deb

s39_debr = _ida_allins.s39_debr

s39_der = _ida_allins.s39_der

s39_dfltcc = _ida_allins.s39_dfltcc

s39_diag = _ida_allins.s39_diag

s39_didbr = _ida_allins.s39_didbr

s39_diebr = _ida_allins.s39_diebr

s39_dl = _ida_allins.s39_dl

s39_dlg = _ida_allins.s39_dlg

s39_dlgr = _ida_allins.s39_dlgr

s39_dlr = _ida_allins.s39_dlr

s39_dp = _ida_allins.s39_dp

s39_dr = _ida_allins.s39_dr

s39_dsg = _ida_allins.s39_dsg

s39_dsgf = _ida_allins.s39_dsgf

s39_dsgfr = _ida_allins.s39_dsgfr

s39_dsgr = _ida_allins.s39_dsgr

s39_dxbr = _ida_allins.s39_dxbr

s39_dxr = _ida_allins.s39_dxr

s39_dxtr = _ida_allins.s39_dxtr

s39_dxtra = _ida_allins.s39_dxtra

s39_ear = _ida_allins.s39_ear

s39_ecag = _ida_allins.s39_ecag

s39_ecctr = _ida_allins.s39_ecctr

s39_ecpga = _ida_allins.s39_ecpga

s39_ectg = _ida_allins.s39_ectg

s39_ed = _ida_allins.s39_ed

s39_edmk = _ida_allins.s39_edmk

s39_eedtr = _ida_allins.s39_eedtr

s39_eextr = _ida_allins.s39_eextr

s39_efpc = _ida_allins.s39_efpc

s39_epair = _ida_allins.s39_epair

s39_epar = _ida_allins.s39_epar

s39_epctr = _ida_allins.s39_epctr

s39_epsw = _ida_allins.s39_epsw

s39_ereg = _ida_allins.s39_ereg

s39_eregg = _ida_allins.s39_eregg

s39_esair = _ida_allins.s39_esair

s39_esar = _ida_allins.s39_esar

s39_esdtr = _ida_allins.s39_esdtr

s39_esea = _ida_allins.s39_esea

s39_esta = _ida_allins.s39_esta

s39_esxtr = _ida_allins.s39_esxtr

s39_etnd = _ida_allins.s39_etnd

s39_ex = _ida_allins.s39_ex

s39_exrl = _ida_allins.s39_exrl

s39_fidbr = _ida_allins.s39_fidbr

s39_fidbra = _ida_allins.s39_fidbra

s39_fidr = _ida_allins.s39_fidr

s39_fidtr = _ida_allins.s39_fidtr

s39_fiebr = _ida_allins.s39_fiebr

s39_fiebra = _ida_allins.s39_fiebra

s39_fier = _ida_allins.s39_fier

s39_fixbr = _ida_allins.s39_fixbr

s39_fixbra = _ida_allins.s39_fixbra

s39_fixr = _ida_allins.s39_fixr

s39_fixtr = _ida_allins.s39_fixtr

s39_flogr = _ida_allins.s39_flogr

s39_hdr = _ida_allins.s39_hdr

s39_her = _ida_allins.s39_her

s39_hsch = _ida_allins.s39_hsch

s39_iac = _ida_allins.s39_iac

s39_ic = _ida_allins.s39_ic

s39_icm = _ida_allins.s39_icm

s39_icmh = _ida_allins.s39_icmh

s39_icmy = _ida_allins.s39_icmy

s39_icy = _ida_allins.s39_icy

s39_idte = _ida_allins.s39_idte

s39_iedtr = _ida_allins.s39_iedtr

s39_iextr = _ida_allins.s39_iextr

s39_iihf = _ida_allins.s39_iihf

s39_iihh = _ida_allins.s39_iihh

s39_iihl = _ida_allins.s39_iihl

s39_iilf = _ida_allins.s39_iilf

s39_iilh = _ida_allins.s39_iilh

s39_iill = _ida_allins.s39_iill

s39_ipk = _ida_allins.s39_ipk

s39_ipm = _ida_allins.s39_ipm

s39_ipte = _ida_allins.s39_ipte

s39_irbm = _ida_allins.s39_irbm

s39_iske = _ida_allins.s39_iske

s39_ivsk = _ida_allins.s39_ivsk

s39_j = _ida_allins.s39_j

s39_jo = _ida_allins.s39_jo

s39_jh = _ida_allins.s39_jh

s39_jnle = _ida_allins.s39_jnle

s39_jl = _ida_allins.s39_jl

s39_jnhe = _ida_allins.s39_jnhe

s39_jlh = _ida_allins.s39_jlh

s39_jne = _ida_allins.s39_jne

s39_je = _ida_allins.s39_je

s39_jnlh = _ida_allins.s39_jnlh

s39_jhe = _ida_allins.s39_jhe

s39_jnl = _ida_allins.s39_jnl

s39_jle = _ida_allins.s39_jle

s39_jnh = _ida_allins.s39_jnh

s39_jno = _ida_allins.s39_jno

s39_jg = _ida_allins.s39_jg

s39_jgo = _ida_allins.s39_jgo

s39_jgh = _ida_allins.s39_jgh

s39_jgnle = _ida_allins.s39_jgnle

s39_jgl = _ida_allins.s39_jgl

s39_jgnhe = _ida_allins.s39_jgnhe

s39_jglh = _ida_allins.s39_jglh

s39_jgne = _ida_allins.s39_jgne

s39_jge = _ida_allins.s39_jge

s39_jgnlh = _ida_allins.s39_jgnlh

s39_jghe = _ida_allins.s39_jghe

s39_jgnl = _ida_allins.s39_jgnl

s39_jgle = _ida_allins.s39_jgle

s39_jgnh = _ida_allins.s39_jgnh

s39_jgno = _ida_allins.s39_jgno

s39_kdb = _ida_allins.s39_kdb

s39_kdbr = _ida_allins.s39_kdbr

s39_kdsa = _ida_allins.s39_kdsa

s39_kdtr = _ida_allins.s39_kdtr

s39_keb = _ida_allins.s39_keb

s39_kebr = _ida_allins.s39_kebr

s39_kimd = _ida_allins.s39_kimd

s39_klmd = _ida_allins.s39_klmd

s39_km = _ida_allins.s39_km

s39_kma = _ida_allins.s39_kma

s39_kmac = _ida_allins.s39_kmac

s39_kmc = _ida_allins.s39_kmc

s39_kmctr = _ida_allins.s39_kmctr

s39_kmf = _ida_allins.s39_kmf

s39_kmo = _ida_allins.s39_kmo

s39_kxbr = _ida_allins.s39_kxbr

s39_kxtr = _ida_allins.s39_kxtr

s39_l = _ida_allins.s39_l

s39_la = _ida_allins.s39_la

s39_laa = _ida_allins.s39_laa

s39_laag = _ida_allins.s39_laag

s39_laal = _ida_allins.s39_laal

s39_laalg = _ida_allins.s39_laalg

s39_lae = _ida_allins.s39_lae

s39_laey = _ida_allins.s39_laey

s39_lam = _ida_allins.s39_lam

s39_lamy = _ida_allins.s39_lamy

s39_lan = _ida_allins.s39_lan

s39_lang = _ida_allins.s39_lang

s39_lao = _ida_allins.s39_lao

s39_laog = _ida_allins.s39_laog

s39_larl = _ida_allins.s39_larl

s39_lasp = _ida_allins.s39_lasp

s39_lat = _ida_allins.s39_lat

s39_lax = _ida_allins.s39_lax

s39_laxg = _ida_allins.s39_laxg

s39_lay = _ida_allins.s39_lay

s39_lb = _ida_allins.s39_lb

s39_lbh = _ida_allins.s39_lbh

s39_lbr = _ida_allins.s39_lbr

s39_lcbb = _ida_allins.s39_lcbb

s39_lcctl = _ida_allins.s39_lcctl

s39_lcdbr = _ida_allins.s39_lcdbr

s39_lcdfr = _ida_allins.s39_lcdfr

s39_lcdr = _ida_allins.s39_lcdr

s39_lcebr = _ida_allins.s39_lcebr

s39_lcer = _ida_allins.s39_lcer

s39_lcgfr = _ida_allins.s39_lcgfr

s39_lcgr = _ida_allins.s39_lcgr

s39_lcr = _ida_allins.s39_lcr

s39_lctl = _ida_allins.s39_lctl

s39_lctlg = _ida_allins.s39_lctlg

s39_lcxbr = _ida_allins.s39_lcxbr

s39_lcxr = _ida_allins.s39_lcxr

s39_ld = _ida_allins.s39_ld

s39_lde = _ida_allins.s39_lde

s39_ldeb = _ida_allins.s39_ldeb

s39_ldebr = _ida_allins.s39_ldebr

s39_lder = _ida_allins.s39_lder

s39_ldetr = _ida_allins.s39_ldetr

s39_ldgr = _ida_allins.s39_ldgr

s39_ldr = _ida_allins.s39_ldr

s39_ldrv = _ida_allins.s39_ldrv

s39_ldxbr = _ida_allins.s39_ldxbr

s39_ldxbra = _ida_allins.s39_ldxbra

s39_ldxr = _ida_allins.s39_ldxr

s39_ldxtr = _ida_allins.s39_ldxtr

s39_ldy = _ida_allins.s39_ldy

s39_le = _ida_allins.s39_le

s39_ledbr = _ida_allins.s39_ledbr

s39_ledbra = _ida_allins.s39_ledbra

s39_ledr = _ida_allins.s39_ledr

s39_ledtr = _ida_allins.s39_ledtr

s39_ler = _ida_allins.s39_ler

s39_lerv = _ida_allins.s39_lerv

s39_lexbr = _ida_allins.s39_lexbr

s39_lexbra = _ida_allins.s39_lexbra

s39_lexr = _ida_allins.s39_lexr

s39_ley = _ida_allins.s39_ley

s39_lfas = _ida_allins.s39_lfas

s39_lfh = _ida_allins.s39_lfh

s39_lfhat = _ida_allins.s39_lfhat

s39_lfpc = _ida_allins.s39_lfpc

s39_lg = _ida_allins.s39_lg

s39_lgat = _ida_allins.s39_lgat

s39_lgb = _ida_allins.s39_lgb

s39_lgbr = _ida_allins.s39_lgbr

s39_lgdr = _ida_allins.s39_lgdr

s39_lgf = _ida_allins.s39_lgf

s39_lgfi = _ida_allins.s39_lgfi

s39_lgfr = _ida_allins.s39_lgfr

s39_lgfrl = _ida_allins.s39_lgfrl

s39_lgg = _ida_allins.s39_lgg

s39_lgh = _ida_allins.s39_lgh

s39_lghi = _ida_allins.s39_lghi

s39_lghr = _ida_allins.s39_lghr

s39_lghrl = _ida_allins.s39_lghrl

s39_lgr = _ida_allins.s39_lgr

s39_lgrl = _ida_allins.s39_lgrl

s39_lgsc = _ida_allins.s39_lgsc

s39_lh = _ida_allins.s39_lh

s39_lhh = _ida_allins.s39_lhh

s39_lhi = _ida_allins.s39_lhi

s39_lhr = _ida_allins.s39_lhr

s39_lhrl = _ida_allins.s39_lhrl

s39_lhy = _ida_allins.s39_lhy

s39_llc = _ida_allins.s39_llc

s39_llch = _ida_allins.s39_llch

s39_llcr = _ida_allins.s39_llcr

s39_llgc = _ida_allins.s39_llgc

s39_llgcr = _ida_allins.s39_llgcr

s39_llgf = _ida_allins.s39_llgf

s39_llgfat = _ida_allins.s39_llgfat

s39_llgfr = _ida_allins.s39_llgfr

s39_llgfrl = _ida_allins.s39_llgfrl

s39_llgfsg = _ida_allins.s39_llgfsg

s39_llgh = _ida_allins.s39_llgh

s39_llghr = _ida_allins.s39_llghr

s39_llghrl = _ida_allins.s39_llghrl

s39_llgt = _ida_allins.s39_llgt

s39_llgtat = _ida_allins.s39_llgtat

s39_llgtr = _ida_allins.s39_llgtr

s39_llh = _ida_allins.s39_llh

s39_llhh = _ida_allins.s39_llhh

s39_llhr = _ida_allins.s39_llhr

s39_llhrl = _ida_allins.s39_llhrl

s39_llihf = _ida_allins.s39_llihf

s39_llihh = _ida_allins.s39_llihh

s39_llihl = _ida_allins.s39_llihl

s39_llilf = _ida_allins.s39_llilf

s39_llilh = _ida_allins.s39_llilh

s39_llill = _ida_allins.s39_llill

s39_llzrgf = _ida_allins.s39_llzrgf

s39_lm = _ida_allins.s39_lm

s39_lmd = _ida_allins.s39_lmd

s39_lmg = _ida_allins.s39_lmg

s39_lmh = _ida_allins.s39_lmh

s39_lmy = _ida_allins.s39_lmy

s39_lndbr = _ida_allins.s39_lndbr

s39_lndfr = _ida_allins.s39_lndfr

s39_lndr = _ida_allins.s39_lndr

s39_lnebr = _ida_allins.s39_lnebr

s39_lner = _ida_allins.s39_lner

s39_lngfr = _ida_allins.s39_lngfr

s39_lngr = _ida_allins.s39_lngr

s39_lnr = _ida_allins.s39_lnr

s39_lnxbr = _ida_allins.s39_lnxbr

s39_lnxr = _ida_allins.s39_lnxr

s39_loc = _ida_allins.s39_loc

s39_loco = _ida_allins.s39_loco

s39_loch = _ida_allins.s39_loch

s39_locnle = _ida_allins.s39_locnle

s39_locl = _ida_allins.s39_locl

s39_locnhe = _ida_allins.s39_locnhe

s39_loclh = _ida_allins.s39_loclh

s39_locne = _ida_allins.s39_locne

s39_loce = _ida_allins.s39_loce

s39_locnlh = _ida_allins.s39_locnlh

s39_loche = _ida_allins.s39_loche

s39_locnl = _ida_allins.s39_locnl

s39_locle = _ida_allins.s39_locle

s39_locnh = _ida_allins.s39_locnh

s39_locno = _ida_allins.s39_locno

s39_locfh = _ida_allins.s39_locfh

s39_locfho = _ida_allins.s39_locfho

s39_locfhh = _ida_allins.s39_locfhh

s39_locfhnle = _ida_allins.s39_locfhnle

s39_locfhl = _ida_allins.s39_locfhl

s39_locfhnhe = _ida_allins.s39_locfhnhe

s39_locfhlh = _ida_allins.s39_locfhlh

s39_locfhne = _ida_allins.s39_locfhne

s39_locfhe = _ida_allins.s39_locfhe

s39_locfhnlh = _ida_allins.s39_locfhnlh

s39_locfhhe = _ida_allins.s39_locfhhe

s39_locfhnl = _ida_allins.s39_locfhnl

s39_locfhle = _ida_allins.s39_locfhle

s39_locfhnh = _ida_allins.s39_locfhnh

s39_locfhno = _ida_allins.s39_locfhno

s39_locfhr = _ida_allins.s39_locfhr

s39_locfhro = _ida_allins.s39_locfhro

s39_locfhrh = _ida_allins.s39_locfhrh

s39_locfhrnle = _ida_allins.s39_locfhrnle

s39_locfhrl = _ida_allins.s39_locfhrl

s39_locfhrnhe = _ida_allins.s39_locfhrnhe

s39_locfhrlh = _ida_allins.s39_locfhrlh

s39_locfhrne = _ida_allins.s39_locfhrne

s39_locfhre = _ida_allins.s39_locfhre

s39_locfhrnlh = _ida_allins.s39_locfhrnlh

s39_locfhrhe = _ida_allins.s39_locfhrhe

s39_locfhrnl = _ida_allins.s39_locfhrnl

s39_locfhrle = _ida_allins.s39_locfhrle

s39_locfhrnh = _ida_allins.s39_locfhrnh

s39_locfhrno = _ida_allins.s39_locfhrno

s39_locg = _ida_allins.s39_locg

s39_locgo = _ida_allins.s39_locgo

s39_locgh = _ida_allins.s39_locgh

s39_locgnle = _ida_allins.s39_locgnle

s39_locgl = _ida_allins.s39_locgl

s39_locgnhe = _ida_allins.s39_locgnhe

s39_locglh = _ida_allins.s39_locglh

s39_locgne = _ida_allins.s39_locgne

s39_locge = _ida_allins.s39_locge

s39_locgnlh = _ida_allins.s39_locgnlh

s39_locghe = _ida_allins.s39_locghe

s39_locgnl = _ida_allins.s39_locgnl

s39_locgle = _ida_allins.s39_locgle

s39_locgnh = _ida_allins.s39_locgnh

s39_locgno = _ida_allins.s39_locgno

s39_locghi = _ida_allins.s39_locghi

s39_locghio = _ida_allins.s39_locghio

s39_locghih = _ida_allins.s39_locghih

s39_locghinle = _ida_allins.s39_locghinle

s39_locghil = _ida_allins.s39_locghil

s39_locghinhe = _ida_allins.s39_locghinhe

s39_locghilh = _ida_allins.s39_locghilh

s39_locghine = _ida_allins.s39_locghine

s39_locghie = _ida_allins.s39_locghie

s39_locghinlh = _ida_allins.s39_locghinlh

s39_locghihe = _ida_allins.s39_locghihe

s39_locghinl = _ida_allins.s39_locghinl

s39_locghile = _ida_allins.s39_locghile

s39_locghinh = _ida_allins.s39_locghinh

s39_locghino = _ida_allins.s39_locghino

s39_locgr = _ida_allins.s39_locgr

s39_locgro = _ida_allins.s39_locgro

s39_locgrh = _ida_allins.s39_locgrh

s39_locgrnle = _ida_allins.s39_locgrnle

s39_locgrl = _ida_allins.s39_locgrl

s39_locgrnhe = _ida_allins.s39_locgrnhe

s39_locgrlh = _ida_allins.s39_locgrlh

s39_locgrne = _ida_allins.s39_locgrne

s39_locgre = _ida_allins.s39_locgre

s39_locgrnlh = _ida_allins.s39_locgrnlh

s39_locgrhe = _ida_allins.s39_locgrhe

s39_locgrnl = _ida_allins.s39_locgrnl

s39_locgrle = _ida_allins.s39_locgrle

s39_locgrnh = _ida_allins.s39_locgrnh

s39_locgrno = _ida_allins.s39_locgrno

s39_lochhi = _ida_allins.s39_lochhi

s39_lochhio = _ida_allins.s39_lochhio

s39_lochhih = _ida_allins.s39_lochhih

s39_lochhinle = _ida_allins.s39_lochhinle

s39_lochhil = _ida_allins.s39_lochhil

s39_lochhinhe = _ida_allins.s39_lochhinhe

s39_lochhilh = _ida_allins.s39_lochhilh

s39_lochhine = _ida_allins.s39_lochhine

s39_lochhie = _ida_allins.s39_lochhie

s39_lochhinlh = _ida_allins.s39_lochhinlh

s39_lochhihe = _ida_allins.s39_lochhihe

s39_lochhinl = _ida_allins.s39_lochhinl

s39_lochhile = _ida_allins.s39_lochhile

s39_lochhinh = _ida_allins.s39_lochhinh

s39_lochhino = _ida_allins.s39_lochhino

s39_lochi = _ida_allins.s39_lochi

s39_lochio = _ida_allins.s39_lochio

s39_lochih = _ida_allins.s39_lochih

s39_lochinle = _ida_allins.s39_lochinle

s39_lochil = _ida_allins.s39_lochil

s39_lochinhe = _ida_allins.s39_lochinhe

s39_lochilh = _ida_allins.s39_lochilh

s39_lochine = _ida_allins.s39_lochine

s39_lochie = _ida_allins.s39_lochie

s39_lochinlh = _ida_allins.s39_lochinlh

s39_lochihe = _ida_allins.s39_lochihe

s39_lochinl = _ida_allins.s39_lochinl

s39_lochile = _ida_allins.s39_lochile

s39_lochinh = _ida_allins.s39_lochinh

s39_lochino = _ida_allins.s39_lochino

s39_locr = _ida_allins.s39_locr

s39_locro = _ida_allins.s39_locro

s39_locrh = _ida_allins.s39_locrh

s39_locrnle = _ida_allins.s39_locrnle

s39_locrl = _ida_allins.s39_locrl

s39_locrnhe = _ida_allins.s39_locrnhe

s39_locrlh = _ida_allins.s39_locrlh

s39_locrne = _ida_allins.s39_locrne

s39_locre = _ida_allins.s39_locre

s39_locrnlh = _ida_allins.s39_locrnlh

s39_locrhe = _ida_allins.s39_locrhe

s39_locrnl = _ida_allins.s39_locrnl

s39_locrle = _ida_allins.s39_locrle

s39_locrnh = _ida_allins.s39_locrnh

s39_locrno = _ida_allins.s39_locrno

s39_lpctl = _ida_allins.s39_lpctl

s39_lpd = _ida_allins.s39_lpd

s39_lpdbr = _ida_allins.s39_lpdbr

s39_lpdfr = _ida_allins.s39_lpdfr

s39_lpdg = _ida_allins.s39_lpdg

s39_lpdr = _ida_allins.s39_lpdr

s39_lpebr = _ida_allins.s39_lpebr

s39_lper = _ida_allins.s39_lper

s39_lpgfr = _ida_allins.s39_lpgfr

s39_lpgr = _ida_allins.s39_lpgr

s39_lpp = _ida_allins.s39_lpp

s39_lpq = _ida_allins.s39_lpq

s39_lpr = _ida_allins.s39_lpr

s39_lpsw = _ida_allins.s39_lpsw

s39_lpswe = _ida_allins.s39_lpswe

s39_lptea = _ida_allins.s39_lptea

s39_lpxbr = _ida_allins.s39_lpxbr

s39_lpxr = _ida_allins.s39_lpxr

s39_lr = _ida_allins.s39_lr

s39_lra = _ida_allins.s39_lra

s39_lrag = _ida_allins.s39_lrag

s39_lray = _ida_allins.s39_lray

s39_lrdr = _ida_allins.s39_lrdr

s39_lrer = _ida_allins.s39_lrer

s39_lrl = _ida_allins.s39_lrl

s39_lrv = _ida_allins.s39_lrv

s39_lrvg = _ida_allins.s39_lrvg

s39_lrvgr = _ida_allins.s39_lrvgr

s39_lrvh = _ida_allins.s39_lrvh

s39_lrvr = _ida_allins.s39_lrvr

s39_lsctl = _ida_allins.s39_lsctl

s39_lt = _ida_allins.s39_lt

s39_ltdbr = _ida_allins.s39_ltdbr

s39_ltdr = _ida_allins.s39_ltdr

s39_ltdtr = _ida_allins.s39_ltdtr

s39_ltebr = _ida_allins.s39_ltebr

s39_lter = _ida_allins.s39_lter

s39_ltg = _ida_allins.s39_ltg

s39_ltgf = _ida_allins.s39_ltgf

s39_ltgfr = _ida_allins.s39_ltgfr

s39_ltgr = _ida_allins.s39_ltgr

s39_ltr = _ida_allins.s39_ltr

s39_ltxbr = _ida_allins.s39_ltxbr

s39_ltxr = _ida_allins.s39_ltxr

s39_ltxtr = _ida_allins.s39_ltxtr

s39_lura = _ida_allins.s39_lura

s39_lurag = _ida_allins.s39_lurag

s39_lxd = _ida_allins.s39_lxd

s39_lxdb = _ida_allins.s39_lxdb

s39_lxdbr = _ida_allins.s39_lxdbr

s39_lxdr = _ida_allins.s39_lxdr

s39_lxdtr = _ida_allins.s39_lxdtr

s39_lxe = _ida_allins.s39_lxe

s39_lxeb = _ida_allins.s39_lxeb

s39_lxebr = _ida_allins.s39_lxebr

s39_lxer = _ida_allins.s39_lxer

s39_lxr = _ida_allins.s39_lxr

s39_ly = _ida_allins.s39_ly

s39_lzdr = _ida_allins.s39_lzdr

s39_lzer = _ida_allins.s39_lzer

s39_lzrf = _ida_allins.s39_lzrf

s39_lzrg = _ida_allins.s39_lzrg

s39_lzxr = _ida_allins.s39_lzxr

s39_m = _ida_allins.s39_m

s39_mad = _ida_allins.s39_mad

s39_madb = _ida_allins.s39_madb

s39_madbr = _ida_allins.s39_madbr

s39_madr = _ida_allins.s39_madr

s39_mae = _ida_allins.s39_mae

s39_maeb = _ida_allins.s39_maeb

s39_maebr = _ida_allins.s39_maebr

s39_maer = _ida_allins.s39_maer

s39_may = _ida_allins.s39_may

s39_mayh = _ida_allins.s39_mayh

s39_mayhr = _ida_allins.s39_mayhr

s39_mayl = _ida_allins.s39_mayl

s39_maylr = _ida_allins.s39_maylr

s39_mayr = _ida_allins.s39_mayr

s39_mc = _ida_allins.s39_mc

s39_md = _ida_allins.s39_md

s39_mdb = _ida_allins.s39_mdb

s39_mdbr = _ida_allins.s39_mdbr

s39_mde = _ida_allins.s39_mde

s39_mdeb = _ida_allins.s39_mdeb

s39_mdebr = _ida_allins.s39_mdebr

s39_mder = _ida_allins.s39_mder

s39_mdr = _ida_allins.s39_mdr

s39_mdtr = _ida_allins.s39_mdtr

s39_mdtra = _ida_allins.s39_mdtra

s39_me = _ida_allins.s39_me

s39_mee = _ida_allins.s39_mee

s39_meeb = _ida_allins.s39_meeb

s39_meebr = _ida_allins.s39_meebr

s39_meer = _ida_allins.s39_meer

s39_mer = _ida_allins.s39_mer

s39_mfy = _ida_allins.s39_mfy

s39_mg = _ida_allins.s39_mg

s39_mgh = _ida_allins.s39_mgh

s39_mghi = _ida_allins.s39_mghi

s39_mgrk = _ida_allins.s39_mgrk

s39_mh = _ida_allins.s39_mh

s39_mhi = _ida_allins.s39_mhi

s39_mhy = _ida_allins.s39_mhy

s39_ml = _ida_allins.s39_ml

s39_mlg = _ida_allins.s39_mlg

s39_mlgr = _ida_allins.s39_mlgr

s39_mlr = _ida_allins.s39_mlr

s39_mp = _ida_allins.s39_mp

s39_mr = _ida_allins.s39_mr

s39_ms = _ida_allins.s39_ms

s39_msc = _ida_allins.s39_msc

s39_msch = _ida_allins.s39_msch

s39_msd = _ida_allins.s39_msd

s39_msdb = _ida_allins.s39_msdb

s39_msdbr = _ida_allins.s39_msdbr

s39_msdr = _ida_allins.s39_msdr

s39_mse = _ida_allins.s39_mse

s39_mseb = _ida_allins.s39_mseb

s39_msebr = _ida_allins.s39_msebr

s39_mser = _ida_allins.s39_mser

s39_msfi = _ida_allins.s39_msfi

s39_msg = _ida_allins.s39_msg

s39_msgc = _ida_allins.s39_msgc

s39_msgf = _ida_allins.s39_msgf

s39_msgfi = _ida_allins.s39_msgfi

s39_msgfr = _ida_allins.s39_msgfr

s39_msgr = _ida_allins.s39_msgr

s39_msgrkc = _ida_allins.s39_msgrkc

s39_msr = _ida_allins.s39_msr

s39_msrkc = _ida_allins.s39_msrkc

s39_msta = _ida_allins.s39_msta

s39_msy = _ida_allins.s39_msy

s39_mvc = _ida_allins.s39_mvc

s39_mvcdk = _ida_allins.s39_mvcdk

s39_mvcin = _ida_allins.s39_mvcin

s39_mvck = _ida_allins.s39_mvck

s39_mvcl = _ida_allins.s39_mvcl

s39_mvcle = _ida_allins.s39_mvcle

s39_mvclu = _ida_allins.s39_mvclu

s39_mvcos = _ida_allins.s39_mvcos

s39_mvcp = _ida_allins.s39_mvcp

s39_mvcrl = _ida_allins.s39_mvcrl

s39_mvcs = _ida_allins.s39_mvcs

s39_mvcsk = _ida_allins.s39_mvcsk

s39_mvghi = _ida_allins.s39_mvghi

s39_mvhhi = _ida_allins.s39_mvhhi

s39_mvhi = _ida_allins.s39_mvhi

s39_mvi = _ida_allins.s39_mvi

s39_mviy = _ida_allins.s39_mviy

s39_mvn = _ida_allins.s39_mvn

s39_mvo = _ida_allins.s39_mvo

s39_mvpg = _ida_allins.s39_mvpg

s39_mvst = _ida_allins.s39_mvst

s39_mvz = _ida_allins.s39_mvz

s39_mxbr = _ida_allins.s39_mxbr

s39_mxd = _ida_allins.s39_mxd

s39_mxdb = _ida_allins.s39_mxdb

s39_mxdbr = _ida_allins.s39_mxdbr

s39_mxdr = _ida_allins.s39_mxdr

s39_mxr = _ida_allins.s39_mxr

s39_mxtr = _ida_allins.s39_mxtr

s39_mxtra = _ida_allins.s39_mxtra

s39_my = _ida_allins.s39_my

s39_myh = _ida_allins.s39_myh

s39_myhr = _ida_allins.s39_myhr

s39_myl = _ida_allins.s39_myl

s39_mylr = _ida_allins.s39_mylr

s39_myr = _ida_allins.s39_myr

s39_n = _ida_allins.s39_n

s39_nc = _ida_allins.s39_nc

s39_ncgrk = _ida_allins.s39_ncgrk

s39_ncrk = _ida_allins.s39_ncrk

s39_ng = _ida_allins.s39_ng

s39_ngr = _ida_allins.s39_ngr

s39_ngrk = _ida_allins.s39_ngrk

s39_ni = _ida_allins.s39_ni

s39_niai = _ida_allins.s39_niai

s39_nihf = _ida_allins.s39_nihf

s39_nihh = _ida_allins.s39_nihh

s39_nihl = _ida_allins.s39_nihl

s39_nilf = _ida_allins.s39_nilf

s39_nilh = _ida_allins.s39_nilh

s39_nill = _ida_allins.s39_nill

s39_niy = _ida_allins.s39_niy

s39_nngrk = _ida_allins.s39_nngrk

s39_nnrk = _ida_allins.s39_nnrk

s39_nogrk = _ida_allins.s39_nogrk

s39_nop = _ida_allins.s39_nop

s39_nopr = _ida_allins.s39_nopr

s39_nork = _ida_allins.s39_nork

s39_nr = _ida_allins.s39_nr

s39_nrk = _ida_allins.s39_nrk

s39_ntstg = _ida_allins.s39_ntstg

s39_nxgrk = _ida_allins.s39_nxgrk

s39_nxrk = _ida_allins.s39_nxrk

s39_ny = _ida_allins.s39_ny

s39_o = _ida_allins.s39_o

s39_oc = _ida_allins.s39_oc

s39_ocgrk = _ida_allins.s39_ocgrk

s39_ocrk = _ida_allins.s39_ocrk

s39_og = _ida_allins.s39_og

s39_ogr = _ida_allins.s39_ogr

s39_ogrk = _ida_allins.s39_ogrk

s39_oi = _ida_allins.s39_oi

s39_oihf = _ida_allins.s39_oihf

s39_oihh = _ida_allins.s39_oihh

s39_oihl = _ida_allins.s39_oihl

s39_oilf = _ida_allins.s39_oilf

s39_oilh = _ida_allins.s39_oilh

s39_oill = _ida_allins.s39_oill

s39_oiy = _ida_allins.s39_oiy

s39_or = _ida_allins.s39_or

s39_ork = _ida_allins.s39_ork

s39_oy = _ida_allins.s39_oy

s39_pack = _ida_allins.s39_pack

s39_palb = _ida_allins.s39_palb

s39_pc = _ida_allins.s39_pc

s39_pcc = _ida_allins.s39_pcc

s39_pckmo = _ida_allins.s39_pckmo

s39_pfd = _ida_allins.s39_pfd

s39_pfdrl = _ida_allins.s39_pfdrl

s39_pfmf = _ida_allins.s39_pfmf

s39_pfpo = _ida_allins.s39_pfpo

s39_pgin = _ida_allins.s39_pgin

s39_pgout = _ida_allins.s39_pgout

s39_pka = _ida_allins.s39_pka

s39_pku = _ida_allins.s39_pku

s39_plo = _ida_allins.s39_plo

s39_popcnt = _ida_allins.s39_popcnt

s39_ppa = _ida_allins.s39_ppa

s39_ppno = _ida_allins.s39_ppno

s39_pr = _ida_allins.s39_pr

s39_prno = _ida_allins.s39_prno

s39_pt = _ida_allins.s39_pt

s39_ptf = _ida_allins.s39_ptf

s39_ptff = _ida_allins.s39_ptff

s39_pti = _ida_allins.s39_pti

s39_ptlb = _ida_allins.s39_ptlb

s39_qadtr = _ida_allins.s39_qadtr

s39_qaxtr = _ida_allins.s39_qaxtr

s39_qctri = _ida_allins.s39_qctri

s39_qsi = _ida_allins.s39_qsi

s39_rchp = _ida_allins.s39_rchp

s39_risbg = _ida_allins.s39_risbg

s39_risbgn = _ida_allins.s39_risbgn

s39_risbhg = _ida_allins.s39_risbhg

s39_risblg = _ida_allins.s39_risblg

s39_rll = _ida_allins.s39_rll

s39_rllg = _ida_allins.s39_rllg

s39_rnsbg = _ida_allins.s39_rnsbg

s39_rosbg = _ida_allins.s39_rosbg

s39_rp = _ida_allins.s39_rp

s39_rrbe = _ida_allins.s39_rrbe

s39_rrbm = _ida_allins.s39_rrbm

s39_rrdtr = _ida_allins.s39_rrdtr

s39_rrxtr = _ida_allins.s39_rrxtr

s39_rsch = _ida_allins.s39_rsch

s39_rxsbg = _ida_allins.s39_rxsbg

s39_s = _ida_allins.s39_s

s39_sac = _ida_allins.s39_sac

s39_sacf = _ida_allins.s39_sacf

s39_sal = _ida_allins.s39_sal

s39_sam24 = _ida_allins.s39_sam24

s39_sam31 = _ida_allins.s39_sam31

s39_sam64 = _ida_allins.s39_sam64

s39_sar = _ida_allins.s39_sar

s39_scctr = _ida_allins.s39_scctr

s39_schm = _ida_allins.s39_schm

s39_sck = _ida_allins.s39_sck

s39_sckc = _ida_allins.s39_sckc

s39_sckpf = _ida_allins.s39_sckpf

s39_sd = _ida_allins.s39_sd

s39_sdb = _ida_allins.s39_sdb

s39_sdbr = _ida_allins.s39_sdbr

s39_sdr = _ida_allins.s39_sdr

s39_sdtr = _ida_allins.s39_sdtr

s39_sdtra = _ida_allins.s39_sdtra

s39_se = _ida_allins.s39_se

s39_seb = _ida_allins.s39_seb

s39_sebr = _ida_allins.s39_sebr

s39_selgr = _ida_allins.s39_selgr

s39_selgro = _ida_allins.s39_selgro

s39_selgrh = _ida_allins.s39_selgrh

s39_selgrnle = _ida_allins.s39_selgrnle

s39_selgrl = _ida_allins.s39_selgrl

s39_selgrnhe = _ida_allins.s39_selgrnhe

s39_selgrlh = _ida_allins.s39_selgrlh

s39_selgrne = _ida_allins.s39_selgrne

s39_selgre = _ida_allins.s39_selgre

s39_selgrnlh = _ida_allins.s39_selgrnlh

s39_selgrhe = _ida_allins.s39_selgrhe

s39_selgrnl = _ida_allins.s39_selgrnl

s39_selgrle = _ida_allins.s39_selgrle

s39_selgrnh = _ida_allins.s39_selgrnh

s39_selgrno = _ida_allins.s39_selgrno

s39_selhhhr = _ida_allins.s39_selhhhr

s39_selhhhro = _ida_allins.s39_selhhhro

s39_selhhhrh = _ida_allins.s39_selhhhrh

s39_selhhhrnle = _ida_allins.s39_selhhhrnle

s39_selhhhrl = _ida_allins.s39_selhhhrl

s39_selhhhrnhe = _ida_allins.s39_selhhhrnhe

s39_selhhhrlh = _ida_allins.s39_selhhhrlh

s39_selhhhrne = _ida_allins.s39_selhhhrne

s39_selhhhre = _ida_allins.s39_selhhhre

s39_selhhhrnlh = _ida_allins.s39_selhhhrnlh

s39_selhhhrhe = _ida_allins.s39_selhhhrhe

s39_selhhhrnl = _ida_allins.s39_selhhhrnl

s39_selhhhrle = _ida_allins.s39_selhhhrle

s39_selhhhrnh = _ida_allins.s39_selhhhrnh

s39_selhhhrno = _ida_allins.s39_selhhhrno

s39_selr = _ida_allins.s39_selr

s39_selro = _ida_allins.s39_selro

s39_selrh = _ida_allins.s39_selrh

s39_selrnle = _ida_allins.s39_selrnle

s39_selrl = _ida_allins.s39_selrl

s39_selrnhe = _ida_allins.s39_selrnhe

s39_selrlh = _ida_allins.s39_selrlh

s39_selrne = _ida_allins.s39_selrne

s39_selre = _ida_allins.s39_selre

s39_selrnlh = _ida_allins.s39_selrnlh

s39_selrhe = _ida_allins.s39_selrhe

s39_selrnl = _ida_allins.s39_selrnl

s39_selrle = _ida_allins.s39_selrle

s39_selrnh = _ida_allins.s39_selrnh

s39_selrno = _ida_allins.s39_selrno

s39_ser = _ida_allins.s39_ser

s39_sfasr = _ida_allins.s39_sfasr

s39_sfpc = _ida_allins.s39_sfpc

s39_sg = _ida_allins.s39_sg

s39_sgf = _ida_allins.s39_sgf

s39_sgfr = _ida_allins.s39_sgfr

s39_sgh = _ida_allins.s39_sgh

s39_sgr = _ida_allins.s39_sgr

s39_sgrk = _ida_allins.s39_sgrk

s39_sh = _ida_allins.s39_sh

s39_shhhr = _ida_allins.s39_shhhr

s39_shhlr = _ida_allins.s39_shhlr

s39_shy = _ida_allins.s39_shy

s39_sie = _ida_allins.s39_sie

s39_siga = _ida_allins.s39_siga

s39_sigp = _ida_allins.s39_sigp

s39_sl = _ida_allins.s39_sl

s39_sla = _ida_allins.s39_sla

s39_slag = _ida_allins.s39_slag

s39_slak = _ida_allins.s39_slak

s39_slb = _ida_allins.s39_slb

s39_slbg = _ida_allins.s39_slbg

s39_slbgr = _ida_allins.s39_slbgr

s39_slbr = _ida_allins.s39_slbr

s39_slda = _ida_allins.s39_slda

s39_sldl = _ida_allins.s39_sldl

s39_sldt = _ida_allins.s39_sldt

s39_slfi = _ida_allins.s39_slfi

s39_slg = _ida_allins.s39_slg

s39_slgf = _ida_allins.s39_slgf

s39_slgfi = _ida_allins.s39_slgfi

s39_slgfr = _ida_allins.s39_slgfr

s39_slgr = _ida_allins.s39_slgr

s39_slgrk = _ida_allins.s39_slgrk

s39_slhhhr = _ida_allins.s39_slhhhr

s39_slhhlr = _ida_allins.s39_slhhlr

s39_sll = _ida_allins.s39_sll

s39_sllg = _ida_allins.s39_sllg

s39_sllk = _ida_allins.s39_sllk

s39_slr = _ida_allins.s39_slr

s39_slrk = _ida_allins.s39_slrk

s39_slxt = _ida_allins.s39_slxt

s39_sly = _ida_allins.s39_sly

s39_sortl = _ida_allins.s39_sortl

s39_sp = _ida_allins.s39_sp

s39_spctr = _ida_allins.s39_spctr

s39_spka = _ida_allins.s39_spka

s39_spm = _ida_allins.s39_spm

s39_spt = _ida_allins.s39_spt

s39_spx = _ida_allins.s39_spx

s39_sqd = _ida_allins.s39_sqd

s39_sqdb = _ida_allins.s39_sqdb

s39_sqdbr = _ida_allins.s39_sqdbr

s39_sqdr = _ida_allins.s39_sqdr

s39_sqe = _ida_allins.s39_sqe

s39_sqeb = _ida_allins.s39_sqeb

s39_sqebr = _ida_allins.s39_sqebr

s39_sqer = _ida_allins.s39_sqer

s39_sqxbr = _ida_allins.s39_sqxbr

s39_sqxr = _ida_allins.s39_sqxr

s39_sr = _ida_allins.s39_sr

s39_sra = _ida_allins.s39_sra

s39_srag = _ida_allins.s39_srag

s39_srak = _ida_allins.s39_srak

s39_srda = _ida_allins.s39_srda

s39_srdl = _ida_allins.s39_srdl

s39_srdt = _ida_allins.s39_srdt

s39_srk = _ida_allins.s39_srk

s39_srl = _ida_allins.s39_srl

s39_srlg = _ida_allins.s39_srlg

s39_srlk = _ida_allins.s39_srlk

s39_srnm = _ida_allins.s39_srnm

s39_srnmb = _ida_allins.s39_srnmb

s39_srnmt = _ida_allins.s39_srnmt

s39_srp = _ida_allins.s39_srp

s39_srst = _ida_allins.s39_srst

s39_srstu = _ida_allins.s39_srstu

s39_srxt = _ida_allins.s39_srxt

s39_ssair = _ida_allins.s39_ssair

s39_ssar = _ida_allins.s39_ssar

s39_ssch = _ida_allins.s39_ssch

s39_sske = _ida_allins.s39_sske

s39_ssm = _ida_allins.s39_ssm

s39_st = _ida_allins.s39_st

s39_stam = _ida_allins.s39_stam

s39_stamy = _ida_allins.s39_stamy

s39_stap = _ida_allins.s39_stap

s39_stc = _ida_allins.s39_stc

s39_stch = _ida_allins.s39_stch

s39_stck = _ida_allins.s39_stck

s39_stckc = _ida_allins.s39_stckc

s39_stcke = _ida_allins.s39_stcke

s39_stckf = _ida_allins.s39_stckf

s39_stcm = _ida_allins.s39_stcm

s39_stcmh = _ida_allins.s39_stcmh

s39_stcmy = _ida_allins.s39_stcmy

s39_stcps = _ida_allins.s39_stcps

s39_stcrw = _ida_allins.s39_stcrw

s39_stctg = _ida_allins.s39_stctg

s39_stctl = _ida_allins.s39_stctl

s39_stcy = _ida_allins.s39_stcy

s39_std = _ida_allins.s39_std

s39_stdrv = _ida_allins.s39_stdrv

s39_stdy = _ida_allins.s39_stdy

s39_ste = _ida_allins.s39_ste

s39_sterv = _ida_allins.s39_sterv

s39_stey = _ida_allins.s39_stey

s39_stfh = _ida_allins.s39_stfh

s39_stfl = _ida_allins.s39_stfl

s39_stfle = _ida_allins.s39_stfle

s39_stfpc = _ida_allins.s39_stfpc

s39_stg = _ida_allins.s39_stg

s39_stgrl = _ida_allins.s39_stgrl

s39_stgsc = _ida_allins.s39_stgsc

s39_sth = _ida_allins.s39_sth

s39_sthh = _ida_allins.s39_sthh

s39_sthrl = _ida_allins.s39_sthrl

s39_sthy = _ida_allins.s39_sthy

s39_stidp = _ida_allins.s39_stidp

s39_stm = _ida_allins.s39_stm

s39_stmg = _ida_allins.s39_stmg

s39_stmh = _ida_allins.s39_stmh

s39_stmy = _ida_allins.s39_stmy

s39_stnsm = _ida_allins.s39_stnsm

s39_stoc = _ida_allins.s39_stoc

s39_stoco = _ida_allins.s39_stoco

s39_stoch = _ida_allins.s39_stoch

s39_stocnle = _ida_allins.s39_stocnle

s39_stocl = _ida_allins.s39_stocl

s39_stocnhe = _ida_allins.s39_stocnhe

s39_stoclh = _ida_allins.s39_stoclh

s39_stocne = _ida_allins.s39_stocne

s39_stoce = _ida_allins.s39_stoce

s39_stocnlh = _ida_allins.s39_stocnlh

s39_stoche = _ida_allins.s39_stoche

s39_stocnl = _ida_allins.s39_stocnl

s39_stocle = _ida_allins.s39_stocle

s39_stocnh = _ida_allins.s39_stocnh

s39_stocno = _ida_allins.s39_stocno

s39_stocfh = _ida_allins.s39_stocfh

s39_stocfho = _ida_allins.s39_stocfho

s39_stocfhh = _ida_allins.s39_stocfhh

s39_stocfhnle = _ida_allins.s39_stocfhnle

s39_stocfhl = _ida_allins.s39_stocfhl

s39_stocfhnhe = _ida_allins.s39_stocfhnhe

s39_stocfhlh = _ida_allins.s39_stocfhlh

s39_stocfhne = _ida_allins.s39_stocfhne

s39_stocfhe = _ida_allins.s39_stocfhe

s39_stocfhnlh = _ida_allins.s39_stocfhnlh

s39_stocfhhe = _ida_allins.s39_stocfhhe

s39_stocfhnl = _ida_allins.s39_stocfhnl

s39_stocfhle = _ida_allins.s39_stocfhle

s39_stocfhnh = _ida_allins.s39_stocfhnh

s39_stocfhno = _ida_allins.s39_stocfhno

s39_stocg = _ida_allins.s39_stocg

s39_stocgo = _ida_allins.s39_stocgo

s39_stocgh = _ida_allins.s39_stocgh

s39_stocgnle = _ida_allins.s39_stocgnle

s39_stocgl = _ida_allins.s39_stocgl

s39_stocgnhe = _ida_allins.s39_stocgnhe

s39_stocglh = _ida_allins.s39_stocglh

s39_stocgne = _ida_allins.s39_stocgne

s39_stocge = _ida_allins.s39_stocge

s39_stocgnlh = _ida_allins.s39_stocgnlh

s39_stocghe = _ida_allins.s39_stocghe

s39_stocgnl = _ida_allins.s39_stocgnl

s39_stocgle = _ida_allins.s39_stocgle

s39_stocgnh = _ida_allins.s39_stocgnh

s39_stocgno = _ida_allins.s39_stocgno

s39_stosm = _ida_allins.s39_stosm

s39_stpq = _ida_allins.s39_stpq

s39_stpt = _ida_allins.s39_stpt

s39_stpx = _ida_allins.s39_stpx

s39_strag = _ida_allins.s39_strag

s39_strl = _ida_allins.s39_strl

s39_strv = _ida_allins.s39_strv

s39_strvg = _ida_allins.s39_strvg

s39_strvh = _ida_allins.s39_strvh

s39_stsch = _ida_allins.s39_stsch

s39_stsi = _ida_allins.s39_stsi

s39_stura = _ida_allins.s39_stura

s39_sturg = _ida_allins.s39_sturg

s39_sty = _ida_allins.s39_sty

s39_su = _ida_allins.s39_su

s39_sur = _ida_allins.s39_sur

s39_svc = _ida_allins.s39_svc

s39_sw = _ida_allins.s39_sw

s39_swr = _ida_allins.s39_swr

s39_sxbr = _ida_allins.s39_sxbr

s39_sxr = _ida_allins.s39_sxr

s39_sxtr = _ida_allins.s39_sxtr

s39_sxtra = _ida_allins.s39_sxtra

s39_sy = _ida_allins.s39_sy

s39_tabort = _ida_allins.s39_tabort

s39_tam = _ida_allins.s39_tam

s39_tar = _ida_allins.s39_tar

s39_tb = _ida_allins.s39_tb

s39_tbdr = _ida_allins.s39_tbdr

s39_tbedr = _ida_allins.s39_tbedr

s39_tbegin = _ida_allins.s39_tbegin

s39_tbeginc = _ida_allins.s39_tbeginc

s39_tcdb = _ida_allins.s39_tcdb

s39_tceb = _ida_allins.s39_tceb

s39_tcxb = _ida_allins.s39_tcxb

s39_tdcdt = _ida_allins.s39_tdcdt

s39_tdcet = _ida_allins.s39_tdcet

s39_tdcxt = _ida_allins.s39_tdcxt

s39_tdgdt = _ida_allins.s39_tdgdt

s39_tdget = _ida_allins.s39_tdget

s39_tdgxt = _ida_allins.s39_tdgxt

s39_tend = _ida_allins.s39_tend

s39_thder = _ida_allins.s39_thder

s39_thdr = _ida_allins.s39_thdr

s39_tm = _ida_allins.s39_tm

s39_tmhh = _ida_allins.s39_tmhh

s39_tmhl = _ida_allins.s39_tmhl

s39_tmlh = _ida_allins.s39_tmlh

s39_tmll = _ida_allins.s39_tmll

s39_tmy = _ida_allins.s39_tmy

s39_tp = _ida_allins.s39_tp

s39_tpei = _ida_allins.s39_tpei

s39_tpi = _ida_allins.s39_tpi

s39_tprot = _ida_allins.s39_tprot

s39_tr = _ida_allins.s39_tr

s39_trace = _ida_allins.s39_trace

s39_tracg = _ida_allins.s39_tracg

s39_trap2 = _ida_allins.s39_trap2

s39_trap4 = _ida_allins.s39_trap4

s39_tre = _ida_allins.s39_tre

s39_troo = _ida_allins.s39_troo

s39_trot = _ida_allins.s39_trot

s39_trt = _ida_allins.s39_trt

s39_trte = _ida_allins.s39_trte

s39_trto = _ida_allins.s39_trto

s39_trtr = _ida_allins.s39_trtr

s39_trtre = _ida_allins.s39_trtre

s39_trtt = _ida_allins.s39_trtt

s39_ts = _ida_allins.s39_ts

s39_tsch = _ida_allins.s39_tsch

s39_unpk = _ida_allins.s39_unpk

s39_unpka = _ida_allins.s39_unpka

s39_unpku = _ida_allins.s39_unpku

s39_upt = _ida_allins.s39_upt

s39_va = _ida_allins.s39_va

s39_vab = _ida_allins.s39_vab

s39_vac = _ida_allins.s39_vac

s39_vacc = _ida_allins.s39_vacc

s39_vaccb = _ida_allins.s39_vaccb

s39_vaccc = _ida_allins.s39_vaccc

s39_vacccq = _ida_allins.s39_vacccq

s39_vaccf = _ida_allins.s39_vaccf

s39_vaccg = _ida_allins.s39_vaccg

s39_vacch = _ida_allins.s39_vacch

s39_vaccq = _ida_allins.s39_vaccq

s39_vacq = _ida_allins.s39_vacq

s39_vaf = _ida_allins.s39_vaf

s39_vag = _ida_allins.s39_vag

s39_vah = _ida_allins.s39_vah

s39_vap = _ida_allins.s39_vap

s39_vaq = _ida_allins.s39_vaq

s39_vavg = _ida_allins.s39_vavg

s39_vavgb = _ida_allins.s39_vavgb

s39_vavgf = _ida_allins.s39_vavgf

s39_vavgg = _ida_allins.s39_vavgg

s39_vavgh = _ida_allins.s39_vavgh

s39_vavgl = _ida_allins.s39_vavgl

s39_vavglb = _ida_allins.s39_vavglb

s39_vavglf = _ida_allins.s39_vavglf

s39_vavglg = _ida_allins.s39_vavglg

s39_vavglh = _ida_allins.s39_vavglh

s39_vbperm = _ida_allins.s39_vbperm

s39_vcdg = _ida_allins.s39_vcdg

s39_vcdgb = _ida_allins.s39_vcdgb

s39_vcdlg = _ida_allins.s39_vcdlg

s39_vcdlgb = _ida_allins.s39_vcdlgb

s39_vcefb = _ida_allins.s39_vcefb

s39_vcelfb = _ida_allins.s39_vcelfb

s39_vceq = _ida_allins.s39_vceq

s39_vceqb = _ida_allins.s39_vceqb

s39_vceqbs = _ida_allins.s39_vceqbs

s39_vceqf = _ida_allins.s39_vceqf

s39_vceqfs = _ida_allins.s39_vceqfs

s39_vceqg = _ida_allins.s39_vceqg

s39_vceqgs = _ida_allins.s39_vceqgs

s39_vceqh = _ida_allins.s39_vceqh

s39_vceqhs = _ida_allins.s39_vceqhs

s39_vcfeb = _ida_allins.s39_vcfeb

s39_vcfpl = _ida_allins.s39_vcfpl

s39_vcfps = _ida_allins.s39_vcfps

s39_vcgd = _ida_allins.s39_vcgd

s39_vcgdb = _ida_allins.s39_vcgdb

s39_vch = _ida_allins.s39_vch

s39_vchb = _ida_allins.s39_vchb

s39_vchbs = _ida_allins.s39_vchbs

s39_vchf = _ida_allins.s39_vchf

s39_vchfs = _ida_allins.s39_vchfs

s39_vchg = _ida_allins.s39_vchg

s39_vchgs = _ida_allins.s39_vchgs

s39_vchh = _ida_allins.s39_vchh

s39_vchhs = _ida_allins.s39_vchhs

s39_vchl = _ida_allins.s39_vchl

s39_vchlb = _ida_allins.s39_vchlb

s39_vchlbs = _ida_allins.s39_vchlbs

s39_vchlf = _ida_allins.s39_vchlf

s39_vchlfs = _ida_allins.s39_vchlfs

s39_vchlg = _ida_allins.s39_vchlg

s39_vchlgs = _ida_allins.s39_vchlgs

s39_vchlh = _ida_allins.s39_vchlh

s39_vchlhs = _ida_allins.s39_vchlhs

s39_vcksm = _ida_allins.s39_vcksm

s39_vclfeb = _ida_allins.s39_vclfeb

s39_vclfp = _ida_allins.s39_vclfp

s39_vclgd = _ida_allins.s39_vclgd

s39_vclgdb = _ida_allins.s39_vclgdb

s39_vclz = _ida_allins.s39_vclz

s39_vclzb = _ida_allins.s39_vclzb

s39_vclzf = _ida_allins.s39_vclzf

s39_vclzg = _ida_allins.s39_vclzg

s39_vclzh = _ida_allins.s39_vclzh

s39_vcp = _ida_allins.s39_vcp

s39_vcsfp = _ida_allins.s39_vcsfp

s39_vctz = _ida_allins.s39_vctz

s39_vctzb = _ida_allins.s39_vctzb

s39_vctzf = _ida_allins.s39_vctzf

s39_vctzg = _ida_allins.s39_vctzg

s39_vctzh = _ida_allins.s39_vctzh

s39_vcvb = _ida_allins.s39_vcvb

s39_vcvbg = _ida_allins.s39_vcvbg

s39_vcvd = _ida_allins.s39_vcvd

s39_vcvdg = _ida_allins.s39_vcvdg

s39_vdp = _ida_allins.s39_vdp

s39_vec = _ida_allins.s39_vec

s39_vecb = _ida_allins.s39_vecb

s39_vecf = _ida_allins.s39_vecf

s39_vecg = _ida_allins.s39_vecg

s39_vech = _ida_allins.s39_vech

s39_vecl = _ida_allins.s39_vecl

s39_veclb = _ida_allins.s39_veclb

s39_veclf = _ida_allins.s39_veclf

s39_veclg = _ida_allins.s39_veclg

s39_veclh = _ida_allins.s39_veclh

s39_verim = _ida_allins.s39_verim

s39_verimb = _ida_allins.s39_verimb

s39_verimf = _ida_allins.s39_verimf

s39_verimg = _ida_allins.s39_verimg

s39_verimh = _ida_allins.s39_verimh

s39_verll = _ida_allins.s39_verll

s39_verllb = _ida_allins.s39_verllb

s39_verllf = _ida_allins.s39_verllf

s39_verllg = _ida_allins.s39_verllg

s39_verllh = _ida_allins.s39_verllh

s39_verllv = _ida_allins.s39_verllv

s39_verllvb = _ida_allins.s39_verllvb

s39_verllvf = _ida_allins.s39_verllvf

s39_verllvg = _ida_allins.s39_verllvg

s39_verllvh = _ida_allins.s39_verllvh

s39_vesl = _ida_allins.s39_vesl

s39_veslb = _ida_allins.s39_veslb

s39_veslf = _ida_allins.s39_veslf

s39_veslg = _ida_allins.s39_veslg

s39_veslh = _ida_allins.s39_veslh

s39_veslv = _ida_allins.s39_veslv

s39_veslvb = _ida_allins.s39_veslvb

s39_veslvf = _ida_allins.s39_veslvf

s39_veslvg = _ida_allins.s39_veslvg

s39_veslvh = _ida_allins.s39_veslvh

s39_vesra = _ida_allins.s39_vesra

s39_vesrab = _ida_allins.s39_vesrab

s39_vesraf = _ida_allins.s39_vesraf

s39_vesrag = _ida_allins.s39_vesrag

s39_vesrah = _ida_allins.s39_vesrah

s39_vesrav = _ida_allins.s39_vesrav

s39_vesravb = _ida_allins.s39_vesravb

s39_vesravf = _ida_allins.s39_vesravf

s39_vesravg = _ida_allins.s39_vesravg

s39_vesravh = _ida_allins.s39_vesravh

s39_vesrl = _ida_allins.s39_vesrl

s39_vesrlb = _ida_allins.s39_vesrlb

s39_vesrlf = _ida_allins.s39_vesrlf

s39_vesrlg = _ida_allins.s39_vesrlg

s39_vesrlh = _ida_allins.s39_vesrlh

s39_vesrlv = _ida_allins.s39_vesrlv

s39_vesrlvb = _ida_allins.s39_vesrlvb

s39_vesrlvf = _ida_allins.s39_vesrlvf

s39_vesrlvg = _ida_allins.s39_vesrlvg

s39_vesrlvh = _ida_allins.s39_vesrlvh

s39_vfa = _ida_allins.s39_vfa

s39_vfadb = _ida_allins.s39_vfadb

s39_vfae = _ida_allins.s39_vfae

s39_vfaeb = _ida_allins.s39_vfaeb

s39_vfaebs = _ida_allins.s39_vfaebs

s39_vfaef = _ida_allins.s39_vfaef

s39_vfaefs = _ida_allins.s39_vfaefs

s39_vfaeh = _ida_allins.s39_vfaeh

s39_vfaehs = _ida_allins.s39_vfaehs

s39_vfaezb = _ida_allins.s39_vfaezb

s39_vfaezbs = _ida_allins.s39_vfaezbs

s39_vfaezf = _ida_allins.s39_vfaezf

s39_vfaezfs = _ida_allins.s39_vfaezfs

s39_vfaezh = _ida_allins.s39_vfaezh

s39_vfaezhs = _ida_allins.s39_vfaezhs

s39_vfasb = _ida_allins.s39_vfasb

s39_vfce = _ida_allins.s39_vfce

s39_vfcedb = _ida_allins.s39_vfcedb

s39_vfcedbs = _ida_allins.s39_vfcedbs

s39_vfcesb = _ida_allins.s39_vfcesb

s39_vfcesbs = _ida_allins.s39_vfcesbs

s39_vfch = _ida_allins.s39_vfch

s39_vfchdb = _ida_allins.s39_vfchdb

s39_vfchdbs = _ida_allins.s39_vfchdbs

s39_vfche = _ida_allins.s39_vfche

s39_vfchedb = _ida_allins.s39_vfchedb

s39_vfchedbs = _ida_allins.s39_vfchedbs

s39_vfchesb = _ida_allins.s39_vfchesb

s39_vfchesbs = _ida_allins.s39_vfchesbs

s39_vfchsb = _ida_allins.s39_vfchsb

s39_vfchsbs = _ida_allins.s39_vfchsbs

s39_vfd = _ida_allins.s39_vfd

s39_vfddb = _ida_allins.s39_vfddb

s39_vfdsb = _ida_allins.s39_vfdsb

s39_vfee = _ida_allins.s39_vfee

s39_vfeeb = _ida_allins.s39_vfeeb

s39_vfeebs = _ida_allins.s39_vfeebs

s39_vfeef = _ida_allins.s39_vfeef

s39_vfeefs = _ida_allins.s39_vfeefs

s39_vfeeh = _ida_allins.s39_vfeeh

s39_vfeehs = _ida_allins.s39_vfeehs

s39_vfeezb = _ida_allins.s39_vfeezb

s39_vfeezbs = _ida_allins.s39_vfeezbs

s39_vfeezf = _ida_allins.s39_vfeezf

s39_vfeezfs = _ida_allins.s39_vfeezfs

s39_vfeezh = _ida_allins.s39_vfeezh

s39_vfeezhs = _ida_allins.s39_vfeezhs

s39_vfene = _ida_allins.s39_vfene

s39_vfeneb = _ida_allins.s39_vfeneb

s39_vfenebs = _ida_allins.s39_vfenebs

s39_vfenef = _ida_allins.s39_vfenef

s39_vfenefs = _ida_allins.s39_vfenefs

s39_vfeneh = _ida_allins.s39_vfeneh

s39_vfenehs = _ida_allins.s39_vfenehs

s39_vfenezb = _ida_allins.s39_vfenezb

s39_vfenezbs = _ida_allins.s39_vfenezbs

s39_vfenezf = _ida_allins.s39_vfenezf

s39_vfenezfs = _ida_allins.s39_vfenezfs

s39_vfenezh = _ida_allins.s39_vfenezh

s39_vfenezhs = _ida_allins.s39_vfenezhs

s39_vfi = _ida_allins.s39_vfi

s39_vfidb = _ida_allins.s39_vfidb

s39_vfisb = _ida_allins.s39_vfisb

s39_vfkedb = _ida_allins.s39_vfkedb

s39_vfkedbs = _ida_allins.s39_vfkedbs

s39_vfkesb = _ida_allins.s39_vfkesb

s39_vfkesbs = _ida_allins.s39_vfkesbs

s39_vfkhdb = _ida_allins.s39_vfkhdb

s39_vfkhdbs = _ida_allins.s39_vfkhdbs

s39_vfkhedb = _ida_allins.s39_vfkhedb

s39_vfkhedbs = _ida_allins.s39_vfkhedbs

s39_vfkhesb = _ida_allins.s39_vfkhesb

s39_vfkhesbs = _ida_allins.s39_vfkhesbs

s39_vfkhsb = _ida_allins.s39_vfkhsb

s39_vfkhsbs = _ida_allins.s39_vfkhsbs

s39_vflcdb = _ida_allins.s39_vflcdb

s39_vflcsb = _ida_allins.s39_vflcsb

s39_vfll = _ida_allins.s39_vfll

s39_vflls = _ida_allins.s39_vflls

s39_vflndb = _ida_allins.s39_vflndb

s39_vflnsb = _ida_allins.s39_vflnsb

s39_vflpdb = _ida_allins.s39_vflpdb

s39_vflpsb = _ida_allins.s39_vflpsb

s39_vflr = _ida_allins.s39_vflr

s39_vflrd = _ida_allins.s39_vflrd

s39_vfm = _ida_allins.s39_vfm

s39_vfma = _ida_allins.s39_vfma

s39_vfmadb = _ida_allins.s39_vfmadb

s39_vfmasb = _ida_allins.s39_vfmasb

s39_vfmax = _ida_allins.s39_vfmax

s39_vfmaxdb = _ida_allins.s39_vfmaxdb

s39_vfmaxsb = _ida_allins.s39_vfmaxsb

s39_vfmdb = _ida_allins.s39_vfmdb

s39_vfmin = _ida_allins.s39_vfmin

s39_vfmindb = _ida_allins.s39_vfmindb

s39_vfminsb = _ida_allins.s39_vfminsb

s39_vfms = _ida_allins.s39_vfms

s39_vfmsb = _ida_allins.s39_vfmsb

s39_vfmsdb = _ida_allins.s39_vfmsdb

s39_vfmssb = _ida_allins.s39_vfmssb

s39_vfnma = _ida_allins.s39_vfnma

s39_vfnmadb = _ida_allins.s39_vfnmadb

s39_vfnmasb = _ida_allins.s39_vfnmasb

s39_vfnms = _ida_allins.s39_vfnms

s39_vfnmsdb = _ida_allins.s39_vfnmsdb

s39_vfnmssb = _ida_allins.s39_vfnmssb

s39_vfpso = _ida_allins.s39_vfpso

s39_vfpsodb = _ida_allins.s39_vfpsodb

s39_vfpsosb = _ida_allins.s39_vfpsosb

s39_vfs = _ida_allins.s39_vfs

s39_vfsdb = _ida_allins.s39_vfsdb

s39_vfsq = _ida_allins.s39_vfsq

s39_vfsqdb = _ida_allins.s39_vfsqdb

s39_vfsqsb = _ida_allins.s39_vfsqsb

s39_vfssb = _ida_allins.s39_vfssb

s39_vftci = _ida_allins.s39_vftci

s39_vftcidb = _ida_allins.s39_vftcidb

s39_vftcisb = _ida_allins.s39_vftcisb

s39_vgbm = _ida_allins.s39_vgbm

s39_vgef = _ida_allins.s39_vgef

s39_vgeg = _ida_allins.s39_vgeg

s39_vgfm = _ida_allins.s39_vgfm

s39_vgfma = _ida_allins.s39_vgfma

s39_vgfmab = _ida_allins.s39_vgfmab

s39_vgfmaf = _ida_allins.s39_vgfmaf

s39_vgfmag = _ida_allins.s39_vgfmag

s39_vgfmah = _ida_allins.s39_vgfmah

s39_vgfmb = _ida_allins.s39_vgfmb

s39_vgfmf = _ida_allins.s39_vgfmf

s39_vgfmg = _ida_allins.s39_vgfmg

s39_vgfmh = _ida_allins.s39_vgfmh

s39_vgm = _ida_allins.s39_vgm

s39_vgmb = _ida_allins.s39_vgmb

s39_vgmf = _ida_allins.s39_vgmf

s39_vgmg = _ida_allins.s39_vgmg

s39_vgmh = _ida_allins.s39_vgmh

s39_vistr = _ida_allins.s39_vistr

s39_vistrb = _ida_allins.s39_vistrb

s39_vistrbs = _ida_allins.s39_vistrbs

s39_vistrf = _ida_allins.s39_vistrf

s39_vistrfs = _ida_allins.s39_vistrfs

s39_vistrh = _ida_allins.s39_vistrh

s39_vistrhs = _ida_allins.s39_vistrhs

s39_vl = _ida_allins.s39_vl

s39_vlbb = _ida_allins.s39_vlbb

s39_vlbr = _ida_allins.s39_vlbr

s39_vlbrf = _ida_allins.s39_vlbrf

s39_vlbrg = _ida_allins.s39_vlbrg

s39_vlbrh = _ida_allins.s39_vlbrh

s39_vlbrq = _ida_allins.s39_vlbrq

s39_vlbrrep = _ida_allins.s39_vlbrrep

s39_vlbrrepf = _ida_allins.s39_vlbrrepf

s39_vlbrrepg = _ida_allins.s39_vlbrrepg

s39_vlbrreph = _ida_allins.s39_vlbrreph

s39_vlc = _ida_allins.s39_vlc

s39_vlcb = _ida_allins.s39_vlcb

s39_vlcf = _ida_allins.s39_vlcf

s39_vlcg = _ida_allins.s39_vlcg

s39_vlch = _ida_allins.s39_vlch

s39_vlde = _ida_allins.s39_vlde

s39_vldeb = _ida_allins.s39_vldeb

s39_vleb = _ida_allins.s39_vleb

s39_vlebrf = _ida_allins.s39_vlebrf

s39_vlebrg = _ida_allins.s39_vlebrg

s39_vlebrh = _ida_allins.s39_vlebrh

s39_vled = _ida_allins.s39_vled

s39_vledb = _ida_allins.s39_vledb

s39_vlef = _ida_allins.s39_vlef

s39_vleg = _ida_allins.s39_vleg

s39_vleh = _ida_allins.s39_vleh

s39_vleib = _ida_allins.s39_vleib

s39_vleif = _ida_allins.s39_vleif

s39_vleig = _ida_allins.s39_vleig

s39_vleih = _ida_allins.s39_vleih

s39_vler = _ida_allins.s39_vler

s39_vlerf = _ida_allins.s39_vlerf

s39_vlerg = _ida_allins.s39_vlerg

s39_vlerh = _ida_allins.s39_vlerh

s39_vlgv = _ida_allins.s39_vlgv

s39_vlgvb = _ida_allins.s39_vlgvb

s39_vlgvf = _ida_allins.s39_vlgvf

s39_vlgvg = _ida_allins.s39_vlgvg

s39_vlgvh = _ida_allins.s39_vlgvh

s39_vlip = _ida_allins.s39_vlip

s39_vll = _ida_allins.s39_vll

s39_vllebrz = _ida_allins.s39_vllebrz

s39_vllebrze = _ida_allins.s39_vllebrze

s39_vllebrzf = _ida_allins.s39_vllebrzf

s39_vllebrzg = _ida_allins.s39_vllebrzg

s39_vllebrzh = _ida_allins.s39_vllebrzh

s39_vllez = _ida_allins.s39_vllez

s39_vllezb = _ida_allins.s39_vllezb

s39_vllezf = _ida_allins.s39_vllezf

s39_vllezg = _ida_allins.s39_vllezg

s39_vllezh = _ida_allins.s39_vllezh

s39_vllezlf = _ida_allins.s39_vllezlf

s39_vlm = _ida_allins.s39_vlm

s39_vlp = _ida_allins.s39_vlp

s39_vlpb = _ida_allins.s39_vlpb

s39_vlpf = _ida_allins.s39_vlpf

s39_vlpg = _ida_allins.s39_vlpg

s39_vlph = _ida_allins.s39_vlph

s39_vlr = _ida_allins.s39_vlr

s39_vlrep = _ida_allins.s39_vlrep

s39_vlrepb = _ida_allins.s39_vlrepb

s39_vlrepf = _ida_allins.s39_vlrepf

s39_vlrepg = _ida_allins.s39_vlrepg

s39_vlreph = _ida_allins.s39_vlreph

s39_vlrl = _ida_allins.s39_vlrl

s39_vlrlr = _ida_allins.s39_vlrlr

s39_vlvg = _ida_allins.s39_vlvg

s39_vlvgb = _ida_allins.s39_vlvgb

s39_vlvgf = _ida_allins.s39_vlvgf

s39_vlvgg = _ida_allins.s39_vlvgg

s39_vlvgh = _ida_allins.s39_vlvgh

s39_vlvgp = _ida_allins.s39_vlvgp

s39_vmae = _ida_allins.s39_vmae

s39_vmaeb = _ida_allins.s39_vmaeb

s39_vmaef = _ida_allins.s39_vmaef

s39_vmaeh = _ida_allins.s39_vmaeh

s39_vmah = _ida_allins.s39_vmah

s39_vmahb = _ida_allins.s39_vmahb

s39_vmahf = _ida_allins.s39_vmahf

s39_vmahh = _ida_allins.s39_vmahh

s39_vmal = _ida_allins.s39_vmal

s39_vmalb = _ida_allins.s39_vmalb

s39_vmale = _ida_allins.s39_vmale

s39_vmaleb = _ida_allins.s39_vmaleb

s39_vmalef = _ida_allins.s39_vmalef

s39_vmaleh = _ida_allins.s39_vmaleh

s39_vmalf = _ida_allins.s39_vmalf

s39_vmalh = _ida_allins.s39_vmalh

s39_vmalhb = _ida_allins.s39_vmalhb

s39_vmalhf = _ida_allins.s39_vmalhf

s39_vmalhh = _ida_allins.s39_vmalhh

s39_vmalhw = _ida_allins.s39_vmalhw

s39_vmalo = _ida_allins.s39_vmalo

s39_vmalob = _ida_allins.s39_vmalob

s39_vmalof = _ida_allins.s39_vmalof

s39_vmaloh = _ida_allins.s39_vmaloh

s39_vmao = _ida_allins.s39_vmao

s39_vmaob = _ida_allins.s39_vmaob

s39_vmaof = _ida_allins.s39_vmaof

s39_vmaoh = _ida_allins.s39_vmaoh

s39_vme = _ida_allins.s39_vme

s39_vmeb = _ida_allins.s39_vmeb

s39_vmef = _ida_allins.s39_vmef

s39_vmeh = _ida_allins.s39_vmeh

s39_vmh = _ida_allins.s39_vmh

s39_vmhb = _ida_allins.s39_vmhb

s39_vmhf = _ida_allins.s39_vmhf

s39_vmhh = _ida_allins.s39_vmhh

s39_vml = _ida_allins.s39_vml

s39_vmlb = _ida_allins.s39_vmlb

s39_vmle = _ida_allins.s39_vmle

s39_vmleb = _ida_allins.s39_vmleb

s39_vmlef = _ida_allins.s39_vmlef

s39_vmleh = _ida_allins.s39_vmleh

s39_vmlf = _ida_allins.s39_vmlf

s39_vmlh = _ida_allins.s39_vmlh

s39_vmlhb = _ida_allins.s39_vmlhb

s39_vmlhf = _ida_allins.s39_vmlhf

s39_vmlhh = _ida_allins.s39_vmlhh

s39_vmlhw = _ida_allins.s39_vmlhw

s39_vmlo = _ida_allins.s39_vmlo

s39_vmlob = _ida_allins.s39_vmlob

s39_vmlof = _ida_allins.s39_vmlof

s39_vmloh = _ida_allins.s39_vmloh

s39_vmn = _ida_allins.s39_vmn

s39_vmnb = _ida_allins.s39_vmnb

s39_vmnf = _ida_allins.s39_vmnf

s39_vmng = _ida_allins.s39_vmng

s39_vmnh = _ida_allins.s39_vmnh

s39_vmnl = _ida_allins.s39_vmnl

s39_vmnlb = _ida_allins.s39_vmnlb

s39_vmnlf = _ida_allins.s39_vmnlf

s39_vmnlg = _ida_allins.s39_vmnlg

s39_vmnlh = _ida_allins.s39_vmnlh

s39_vmo = _ida_allins.s39_vmo

s39_vmob = _ida_allins.s39_vmob

s39_vmof = _ida_allins.s39_vmof

s39_vmoh = _ida_allins.s39_vmoh

s39_vmp = _ida_allins.s39_vmp

s39_vmrh = _ida_allins.s39_vmrh

s39_vmrhb = _ida_allins.s39_vmrhb

s39_vmrhf = _ida_allins.s39_vmrhf

s39_vmrhg = _ida_allins.s39_vmrhg

s39_vmrhh = _ida_allins.s39_vmrhh

s39_vmrl = _ida_allins.s39_vmrl

s39_vmrlb = _ida_allins.s39_vmrlb

s39_vmrlf = _ida_allins.s39_vmrlf

s39_vmrlg = _ida_allins.s39_vmrlg

s39_vmrlh = _ida_allins.s39_vmrlh

s39_vmsl = _ida_allins.s39_vmsl

s39_vmslg = _ida_allins.s39_vmslg

s39_vmsp = _ida_allins.s39_vmsp

s39_vmx = _ida_allins.s39_vmx

s39_vmxb = _ida_allins.s39_vmxb

s39_vmxf = _ida_allins.s39_vmxf

s39_vmxg = _ida_allins.s39_vmxg

s39_vmxh = _ida_allins.s39_vmxh

s39_vmxl = _ida_allins.s39_vmxl

s39_vmxlb = _ida_allins.s39_vmxlb

s39_vmxlf = _ida_allins.s39_vmxlf

s39_vmxlg = _ida_allins.s39_vmxlg

s39_vmxlh = _ida_allins.s39_vmxlh

s39_vn = _ida_allins.s39_vn

s39_vnc = _ida_allins.s39_vnc

s39_vnn = _ida_allins.s39_vnn

s39_vno = _ida_allins.s39_vno

s39_vnot = _ida_allins.s39_vnot

s39_vnx = _ida_allins.s39_vnx

s39_vo = _ida_allins.s39_vo

s39_voc = _ida_allins.s39_voc

s39_vone = _ida_allins.s39_vone

s39_vpdi = _ida_allins.s39_vpdi

s39_vperm = _ida_allins.s39_vperm

s39_vpk = _ida_allins.s39_vpk

s39_vpkf = _ida_allins.s39_vpkf

s39_vpkg = _ida_allins.s39_vpkg

s39_vpkh = _ida_allins.s39_vpkh

s39_vpkls = _ida_allins.s39_vpkls

s39_vpklsf = _ida_allins.s39_vpklsf

s39_vpklsfs = _ida_allins.s39_vpklsfs

s39_vpklsg = _ida_allins.s39_vpklsg

s39_vpklsgs = _ida_allins.s39_vpklsgs

s39_vpklsh = _ida_allins.s39_vpklsh

s39_vpklshs = _ida_allins.s39_vpklshs

s39_vpks = _ida_allins.s39_vpks

s39_vpksf = _ida_allins.s39_vpksf

s39_vpksfs = _ida_allins.s39_vpksfs

s39_vpksg = _ida_allins.s39_vpksg

s39_vpksgs = _ida_allins.s39_vpksgs

s39_vpksh = _ida_allins.s39_vpksh

s39_vpkshs = _ida_allins.s39_vpkshs

s39_vpkz = _ida_allins.s39_vpkz

s39_vpopct = _ida_allins.s39_vpopct

s39_vpopctb = _ida_allins.s39_vpopctb

s39_vpopctf = _ida_allins.s39_vpopctf

s39_vpopctg = _ida_allins.s39_vpopctg

s39_vpopcth = _ida_allins.s39_vpopcth

s39_vpsop = _ida_allins.s39_vpsop

s39_vrep = _ida_allins.s39_vrep

s39_vrepb = _ida_allins.s39_vrepb

s39_vrepf = _ida_allins.s39_vrepf

s39_vrepg = _ida_allins.s39_vrepg

s39_vreph = _ida_allins.s39_vreph

s39_vrepi = _ida_allins.s39_vrepi

s39_vrepib = _ida_allins.s39_vrepib

s39_vrepif = _ida_allins.s39_vrepif

s39_vrepig = _ida_allins.s39_vrepig

s39_vrepih = _ida_allins.s39_vrepih

s39_vrp = _ida_allins.s39_vrp

s39_vs = _ida_allins.s39_vs

s39_vsb = _ida_allins.s39_vsb

s39_vsbcbi = _ida_allins.s39_vsbcbi

s39_vsbcbiq = _ida_allins.s39_vsbcbiq

s39_vsbi = _ida_allins.s39_vsbi

s39_vsbiq = _ida_allins.s39_vsbiq

s39_vscbi = _ida_allins.s39_vscbi

s39_vscbib = _ida_allins.s39_vscbib

s39_vscbif = _ida_allins.s39_vscbif

s39_vscbig = _ida_allins.s39_vscbig

s39_vscbih = _ida_allins.s39_vscbih

s39_vscbiq = _ida_allins.s39_vscbiq

s39_vscef = _ida_allins.s39_vscef

s39_vsceg = _ida_allins.s39_vsceg

s39_vsdp = _ida_allins.s39_vsdp

s39_vseg = _ida_allins.s39_vseg

s39_vsegb = _ida_allins.s39_vsegb

s39_vsegf = _ida_allins.s39_vsegf

s39_vsegh = _ida_allins.s39_vsegh

s39_vsel = _ida_allins.s39_vsel

s39_vsf = _ida_allins.s39_vsf

s39_vsg = _ida_allins.s39_vsg

s39_vsh = _ida_allins.s39_vsh

s39_vsl = _ida_allins.s39_vsl

s39_vslb = _ida_allins.s39_vslb

s39_vsld = _ida_allins.s39_vsld

s39_vsldb = _ida_allins.s39_vsldb

s39_vsp = _ida_allins.s39_vsp

s39_vsq = _ida_allins.s39_vsq

s39_vsra = _ida_allins.s39_vsra

s39_vsrab = _ida_allins.s39_vsrab

s39_vsrd = _ida_allins.s39_vsrd

s39_vsrl = _ida_allins.s39_vsrl

s39_vsrlb = _ida_allins.s39_vsrlb

s39_vsrp = _ida_allins.s39_vsrp

s39_vst = _ida_allins.s39_vst

s39_vstbr = _ida_allins.s39_vstbr

s39_vstbrf = _ida_allins.s39_vstbrf

s39_vstbrg = _ida_allins.s39_vstbrg

s39_vstbrh = _ida_allins.s39_vstbrh

s39_vstbrq = _ida_allins.s39_vstbrq

s39_vsteb = _ida_allins.s39_vsteb

s39_vstebrf = _ida_allins.s39_vstebrf

s39_vstebrg = _ida_allins.s39_vstebrg

s39_vstebrh = _ida_allins.s39_vstebrh

s39_vstef = _ida_allins.s39_vstef

s39_vsteg = _ida_allins.s39_vsteg

s39_vsteh = _ida_allins.s39_vsteh

s39_vster = _ida_allins.s39_vster

s39_vsterf = _ida_allins.s39_vsterf

s39_vsterg = _ida_allins.s39_vsterg

s39_vsterh = _ida_allins.s39_vsterh

s39_vstl = _ida_allins.s39_vstl

s39_vstm = _ida_allins.s39_vstm

s39_vstrc = _ida_allins.s39_vstrc

s39_vstrcb = _ida_allins.s39_vstrcb

s39_vstrcbs = _ida_allins.s39_vstrcbs

s39_vstrcf = _ida_allins.s39_vstrcf

s39_vstrcfs = _ida_allins.s39_vstrcfs

s39_vstrch = _ida_allins.s39_vstrch

s39_vstrchs = _ida_allins.s39_vstrchs

s39_vstrczb = _ida_allins.s39_vstrczb

s39_vstrczbs = _ida_allins.s39_vstrczbs

s39_vstrczf = _ida_allins.s39_vstrczf

s39_vstrczfs = _ida_allins.s39_vstrczfs

s39_vstrczh = _ida_allins.s39_vstrczh

s39_vstrczhs = _ida_allins.s39_vstrczhs

s39_vstrl = _ida_allins.s39_vstrl

s39_vstrlr = _ida_allins.s39_vstrlr

s39_vstrs = _ida_allins.s39_vstrs

s39_vstrsb = _ida_allins.s39_vstrsb

s39_vstrsf = _ida_allins.s39_vstrsf

s39_vstrsh = _ida_allins.s39_vstrsh

s39_vstrszb = _ida_allins.s39_vstrszb

s39_vstrszf = _ida_allins.s39_vstrszf

s39_vstrszh = _ida_allins.s39_vstrszh

s39_vsum = _ida_allins.s39_vsum

s39_vsumb = _ida_allins.s39_vsumb

s39_vsumg = _ida_allins.s39_vsumg

s39_vsumgf = _ida_allins.s39_vsumgf

s39_vsumgh = _ida_allins.s39_vsumgh

s39_vsumh = _ida_allins.s39_vsumh

s39_vsumq = _ida_allins.s39_vsumq

s39_vsumqf = _ida_allins.s39_vsumqf

s39_vsumqg = _ida_allins.s39_vsumqg

s39_vtm = _ida_allins.s39_vtm

s39_vtp = _ida_allins.s39_vtp

s39_vuph = _ida_allins.s39_vuph

s39_vuphb = _ida_allins.s39_vuphb

s39_vuphf = _ida_allins.s39_vuphf

s39_vuphh = _ida_allins.s39_vuphh

s39_vupkz = _ida_allins.s39_vupkz

s39_vupl = _ida_allins.s39_vupl

s39_vuplb = _ida_allins.s39_vuplb

s39_vuplf = _ida_allins.s39_vuplf

s39_vuplh = _ida_allins.s39_vuplh

s39_vuplhb = _ida_allins.s39_vuplhb

s39_vuplhf = _ida_allins.s39_vuplhf

s39_vuplhh = _ida_allins.s39_vuplhh

s39_vuplhw = _ida_allins.s39_vuplhw

s39_vupll = _ida_allins.s39_vupll

s39_vupllb = _ida_allins.s39_vupllb

s39_vupllf = _ida_allins.s39_vupllf

s39_vupllh = _ida_allins.s39_vupllh

s39_vzero = _ida_allins.s39_vzero

s39_wcdgb = _ida_allins.s39_wcdgb

s39_wcdlgb = _ida_allins.s39_wcdlgb

s39_wcefb = _ida_allins.s39_wcefb

s39_wcelfb = _ida_allins.s39_wcelfb

s39_wcfeb = _ida_allins.s39_wcfeb

s39_wcgdb = _ida_allins.s39_wcgdb

s39_wclfeb = _ida_allins.s39_wclfeb

s39_wclgdb = _ida_allins.s39_wclgdb

s39_wfadb = _ida_allins.s39_wfadb

s39_wfasb = _ida_allins.s39_wfasb

s39_wfaxb = _ida_allins.s39_wfaxb

s39_wfc = _ida_allins.s39_wfc

s39_wfcdb = _ida_allins.s39_wfcdb

s39_wfcedb = _ida_allins.s39_wfcedb

s39_wfcedbs = _ida_allins.s39_wfcedbs

s39_wfcesb = _ida_allins.s39_wfcesb

s39_wfcesbs = _ida_allins.s39_wfcesbs

s39_wfcexb = _ida_allins.s39_wfcexb

s39_wfcexbs = _ida_allins.s39_wfcexbs

s39_wfchdb = _ida_allins.s39_wfchdb

s39_wfchdbs = _ida_allins.s39_wfchdbs

s39_wfchedb = _ida_allins.s39_wfchedb

s39_wfchedbs = _ida_allins.s39_wfchedbs

s39_wfchesb = _ida_allins.s39_wfchesb

s39_wfchesbs = _ida_allins.s39_wfchesbs

s39_wfchexb = _ida_allins.s39_wfchexb

s39_wfchexbs = _ida_allins.s39_wfchexbs

s39_wfchsb = _ida_allins.s39_wfchsb

s39_wfchsbs = _ida_allins.s39_wfchsbs

s39_wfchxb = _ida_allins.s39_wfchxb

s39_wfchxbs = _ida_allins.s39_wfchxbs

s39_wfcsb = _ida_allins.s39_wfcsb

s39_wfcxb = _ida_allins.s39_wfcxb

s39_wfddb = _ida_allins.s39_wfddb

s39_wfdsb = _ida_allins.s39_wfdsb

s39_wfdxb = _ida_allins.s39_wfdxb

s39_wfidb = _ida_allins.s39_wfidb

s39_wfisb = _ida_allins.s39_wfisb

s39_wfixb = _ida_allins.s39_wfixb

s39_wfk = _ida_allins.s39_wfk

s39_wfkdb = _ida_allins.s39_wfkdb

s39_wfkedb = _ida_allins.s39_wfkedb

s39_wfkedbs = _ida_allins.s39_wfkedbs

s39_wfkesb = _ida_allins.s39_wfkesb

s39_wfkesbs = _ida_allins.s39_wfkesbs

s39_wfkexb = _ida_allins.s39_wfkexb

s39_wfkexbs = _ida_allins.s39_wfkexbs

s39_wfkhdb = _ida_allins.s39_wfkhdb

s39_wfkhdbs = _ida_allins.s39_wfkhdbs

s39_wfkhedb = _ida_allins.s39_wfkhedb

s39_wfkhedbs = _ida_allins.s39_wfkhedbs

s39_wfkhesb = _ida_allins.s39_wfkhesb

s39_wfkhesbs = _ida_allins.s39_wfkhesbs

s39_wfkhexb = _ida_allins.s39_wfkhexb

s39_wfkhexbs = _ida_allins.s39_wfkhexbs

s39_wfkhsb = _ida_allins.s39_wfkhsb

s39_wfkhsbs = _ida_allins.s39_wfkhsbs

s39_wfkhxb = _ida_allins.s39_wfkhxb

s39_wfkhxbs = _ida_allins.s39_wfkhxbs

s39_wfksb = _ida_allins.s39_wfksb

s39_wfkxb = _ida_allins.s39_wfkxb

s39_wflcdb = _ida_allins.s39_wflcdb

s39_wflcsb = _ida_allins.s39_wflcsb

s39_wflcxb = _ida_allins.s39_wflcxb

s39_wflld = _ida_allins.s39_wflld

s39_wflls = _ida_allins.s39_wflls

s39_wflndb = _ida_allins.s39_wflndb

s39_wflnsb = _ida_allins.s39_wflnsb

s39_wflnxb = _ida_allins.s39_wflnxb

s39_wflpdb = _ida_allins.s39_wflpdb

s39_wflpsb = _ida_allins.s39_wflpsb

s39_wflpxb = _ida_allins.s39_wflpxb

s39_wflrd = _ida_allins.s39_wflrd

s39_wflrx = _ida_allins.s39_wflrx

s39_wfmadb = _ida_allins.s39_wfmadb

s39_wfmasb = _ida_allins.s39_wfmasb

s39_wfmaxb = _ida_allins.s39_wfmaxb

s39_wfmaxdb = _ida_allins.s39_wfmaxdb

s39_wfmaxsb = _ida_allins.s39_wfmaxsb

s39_wfmaxxb = _ida_allins.s39_wfmaxxb

s39_wfmdb = _ida_allins.s39_wfmdb

s39_wfmindb = _ida_allins.s39_wfmindb

s39_wfminsb = _ida_allins.s39_wfminsb

s39_wfminxb = _ida_allins.s39_wfminxb

s39_wfmsb = _ida_allins.s39_wfmsb

s39_wfmsdb = _ida_allins.s39_wfmsdb

s39_wfmssb = _ida_allins.s39_wfmssb

s39_wfmsxb = _ida_allins.s39_wfmsxb

s39_wfmxb = _ida_allins.s39_wfmxb

s39_wfnmadb = _ida_allins.s39_wfnmadb

s39_wfnmasb = _ida_allins.s39_wfnmasb

s39_wfnmaxb = _ida_allins.s39_wfnmaxb

s39_wfnmsdb = _ida_allins.s39_wfnmsdb

s39_wfnmssb = _ida_allins.s39_wfnmssb

s39_wfnmsxb = _ida_allins.s39_wfnmsxb

s39_wfpsodb = _ida_allins.s39_wfpsodb

s39_wfpsosb = _ida_allins.s39_wfpsosb

s39_wfpsoxb = _ida_allins.s39_wfpsoxb

s39_wfsdb = _ida_allins.s39_wfsdb

s39_wfsqdb = _ida_allins.s39_wfsqdb

s39_wfsqsb = _ida_allins.s39_wfsqsb

s39_wfsqxb = _ida_allins.s39_wfsqxb

s39_wfssb = _ida_allins.s39_wfssb

s39_wfsxb = _ida_allins.s39_wfsxb

s39_wftcidb = _ida_allins.s39_wftcidb

s39_wftcisb = _ida_allins.s39_wftcisb

s39_wftcixb = _ida_allins.s39_wftcixb

s39_wldeb = _ida_allins.s39_wldeb

s39_wledb = _ida_allins.s39_wledb

s39_x = _ida_allins.s39_x

s39_xc = _ida_allins.s39_xc

s39_xg = _ida_allins.s39_xg

s39_xgr = _ida_allins.s39_xgr

s39_xgrk = _ida_allins.s39_xgrk

s39_xi = _ida_allins.s39_xi

s39_xihf = _ida_allins.s39_xihf

s39_xilf = _ida_allins.s39_xilf

s39_xiy = _ida_allins.s39_xiy

s39_xr = _ida_allins.s39_xr

s39_xrk = _ida_allins.s39_xrk

s39_xsch = _ida_allins.s39_xsch

s39_xy = _ida_allins.s39_xy

s39_zap = _ida_allins.s39_zap

s39_vx = _ida_allins.s39_vx

s39_last = _ida_allins.s39_last

RISCV_null = _ida_allins.RISCV_null

RISCV_lui = _ida_allins.RISCV_lui

RISCV_auipc = _ida_allins.RISCV_auipc

RISCV_jal = _ida_allins.RISCV_jal

RISCV_jalr = _ida_allins.RISCV_jalr

RISCV_beq = _ida_allins.RISCV_beq

RISCV_bne = _ida_allins.RISCV_bne

RISCV_blt = _ida_allins.RISCV_blt

RISCV_bge = _ida_allins.RISCV_bge

RISCV_bltu = _ida_allins.RISCV_bltu

RISCV_bgeu = _ida_allins.RISCV_bgeu

RISCV_lb = _ida_allins.RISCV_lb

RISCV_lh = _ida_allins.RISCV_lh

RISCV_lw = _ida_allins.RISCV_lw

RISCV_lbu = _ida_allins.RISCV_lbu

RISCV_lhu = _ida_allins.RISCV_lhu

RISCV_sb = _ida_allins.RISCV_sb

RISCV_sh = _ida_allins.RISCV_sh

RISCV_sw = _ida_allins.RISCV_sw

RISCV_addi = _ida_allins.RISCV_addi

RISCV_slti = _ida_allins.RISCV_slti

RISCV_sltiu = _ida_allins.RISCV_sltiu

RISCV_xori = _ida_allins.RISCV_xori

RISCV_ori = _ida_allins.RISCV_ori

RISCV_andi = _ida_allins.RISCV_andi

RISCV_slli = _ida_allins.RISCV_slli

RISCV_srli = _ida_allins.RISCV_srli

RISCV_srai = _ida_allins.RISCV_srai

RISCV_add = _ida_allins.RISCV_add

RISCV_sub = _ida_allins.RISCV_sub

RISCV_sll = _ida_allins.RISCV_sll

RISCV_slt = _ida_allins.RISCV_slt

RISCV_sltu = _ida_allins.RISCV_sltu

RISCV_xor = _ida_allins.RISCV_xor

RISCV_srl = _ida_allins.RISCV_srl

RISCV_sra = _ida_allins.RISCV_sra

RISCV_or = _ida_allins.RISCV_or

RISCV_and = _ida_allins.RISCV_and

RISCV_fence = _ida_allins.RISCV_fence

RISCV_ecall = _ida_allins.RISCV_ecall

RISCV_ebreak = _ida_allins.RISCV_ebreak

RISCV_uret = _ida_allins.RISCV_uret

RISCV_sret = _ida_allins.RISCV_sret

RISCV_mret = _ida_allins.RISCV_mret

RISCV_wfi = _ida_allins.RISCV_wfi

RISCV_sfence = _ida_allins.RISCV_sfence

RISCV_hfenceb = _ida_allins.RISCV_hfenceb

RISCV_hfenceg = _ida_allins.RISCV_hfenceg

RISCV_lwu = _ida_allins.RISCV_lwu

RISCV_ld = _ida_allins.RISCV_ld

RISCV_sd = _ida_allins.RISCV_sd

RISCV_addiw = _ida_allins.RISCV_addiw

RISCV_slliw = _ida_allins.RISCV_slliw

RISCV_srliw = _ida_allins.RISCV_srliw

RISCV_sraiw = _ida_allins.RISCV_sraiw

RISCV_addw = _ida_allins.RISCV_addw

RISCV_subw = _ida_allins.RISCV_subw

RISCV_sllw = _ida_allins.RISCV_sllw

RISCV_sltw = _ida_allins.RISCV_sltw

RISCV_srlw = _ida_allins.RISCV_srlw

RISCV_sraw = _ida_allins.RISCV_sraw

RISCV_fencei = _ida_allins.RISCV_fencei

RISCV_csrrw = _ida_allins.RISCV_csrrw

RISCV_csrrs = _ida_allins.RISCV_csrrs

RISCV_csrrc = _ida_allins.RISCV_csrrc

RISCV_csrrwi = _ida_allins.RISCV_csrrwi

RISCV_csrrsi = _ida_allins.RISCV_csrrsi

RISCV_csrrci = _ida_allins.RISCV_csrrci

RISCV_mul = _ida_allins.RISCV_mul

RISCV_mulh = _ida_allins.RISCV_mulh

RISCV_mulhsu = _ida_allins.RISCV_mulhsu

RISCV_mulhu = _ida_allins.RISCV_mulhu

RISCV_div = _ida_allins.RISCV_div

RISCV_divu = _ida_allins.RISCV_divu

RISCV_rem = _ida_allins.RISCV_rem

RISCV_remu = _ida_allins.RISCV_remu

RISCV_mulw = _ida_allins.RISCV_mulw

RISCV_divw = _ida_allins.RISCV_divw

RISCV_divuw = _ida_allins.RISCV_divuw

RISCV_remw = _ida_allins.RISCV_remw

RISCV_remuw = _ida_allins.RISCV_remuw

RISCV_lr = _ida_allins.RISCV_lr

RISCV_sc = _ida_allins.RISCV_sc

RISCV_amoswap = _ida_allins.RISCV_amoswap

RISCV_amoadd = _ida_allins.RISCV_amoadd

RISCV_amoxor = _ida_allins.RISCV_amoxor

RISCV_amoand = _ida_allins.RISCV_amoand

RISCV_amoor = _ida_allins.RISCV_amoor

RISCV_amomin = _ida_allins.RISCV_amomin

RISCV_amomax = _ida_allins.RISCV_amomax

RISCV_amominu = _ida_allins.RISCV_amominu

RISCV_amomaxu = _ida_allins.RISCV_amomaxu

RISCV_flw = _ida_allins.RISCV_flw

RISCV_fsw = _ida_allins.RISCV_fsw

RISCV_fmadd = _ida_allins.RISCV_fmadd

RISCV_fmsub = _ida_allins.RISCV_fmsub

RISCV_fnmsub = _ida_allins.RISCV_fnmsub

RISCV_fnmadd = _ida_allins.RISCV_fnmadd

RISCV_fadd = _ida_allins.RISCV_fadd

RISCV_fsub = _ida_allins.RISCV_fsub

RISCV_fmul = _ida_allins.RISCV_fmul

RISCV_fdiv = _ida_allins.RISCV_fdiv

RISCV_fsqrt = _ida_allins.RISCV_fsqrt

RISCV_fsgnj = _ida_allins.RISCV_fsgnj

RISCV_fsgnjn = _ida_allins.RISCV_fsgnjn

RISCV_fsgnjx = _ida_allins.RISCV_fsgnjx

RISCV_fmin = _ida_allins.RISCV_fmin

RISCV_fmax = _ida_allins.RISCV_fmax

RISCV_fcvtf2f = _ida_allins.RISCV_fcvtf2f

RISCV_fcvtf2i = _ida_allins.RISCV_fcvtf2i

RISCV_fcvti2f = _ida_allins.RISCV_fcvti2f

RISCV_fmv = _ida_allins.RISCV_fmv

RISCV_feq = _ida_allins.RISCV_feq

RISCV_flt = _ida_allins.RISCV_flt

RISCV_fle = _ida_allins.RISCV_fle

RISCV_fclass = _ida_allins.RISCV_fclass

RISCV_fld = _ida_allins.RISCV_fld

RISCV_fsd = _ida_allins.RISCV_fsd

RISCV_flq = _ida_allins.RISCV_flq

RISCV_fsq = _ida_allins.RISCV_fsq

RISCV_nop = _ida_allins.RISCV_nop

RISCV_li = _ida_allins.RISCV_li

RISCV_mv = _ida_allins.RISCV_mv

RISCV_not = _ida_allins.RISCV_not

RISCV_neg = _ida_allins.RISCV_neg

RISCV_negw = _ida_allins.RISCV_negw

RISCV_sext = _ida_allins.RISCV_sext

RISCV_seqz = _ida_allins.RISCV_seqz

RISCV_snez = _ida_allins.RISCV_snez

RISCV_sltz = _ida_allins.RISCV_sltz

RISCV_sgtz = _ida_allins.RISCV_sgtz

RISCV_fabs = _ida_allins.RISCV_fabs

RISCV_fneg = _ida_allins.RISCV_fneg

RISCV_beqz = _ida_allins.RISCV_beqz

RISCV_bnez = _ida_allins.RISCV_bnez

RISCV_blez = _ida_allins.RISCV_blez

RISCV_bgez = _ida_allins.RISCV_bgez

RISCV_bltz = _ida_allins.RISCV_bltz

RISCV_bgtz = _ida_allins.RISCV_bgtz

RISCV_j = _ida_allins.RISCV_j

RISCV_jr = _ida_allins.RISCV_jr

RISCV_ret = _ida_allins.RISCV_ret

RISCV_rdinstret = _ida_allins.RISCV_rdinstret

RISCV_rdcycle = _ida_allins.RISCV_rdcycle

RISCV_rdtime = _ida_allins.RISCV_rdtime

RISCV_rdinstreth = _ida_allins.RISCV_rdinstreth

RISCV_rdcycleh = _ida_allins.RISCV_rdcycleh

RISCV_rdtimeh = _ida_allins.RISCV_rdtimeh

RISCV_csrr = _ida_allins.RISCV_csrr

RISCV_csrw = _ida_allins.RISCV_csrw

RISCV_csrs = _ida_allins.RISCV_csrs

RISCV_csrc = _ida_allins.RISCV_csrc

RISCV_csrwi = _ida_allins.RISCV_csrwi

RISCV_csrsi = _ida_allins.RISCV_csrsi

RISCV_csrci = _ida_allins.RISCV_csrci

RISCV_frcsr = _ida_allins.RISCV_frcsr

RISCV_fscsr = _ida_allins.RISCV_fscsr

RISCV_frrm = _ida_allins.RISCV_frrm

RISCV_fsrm = _ida_allins.RISCV_fsrm

RISCV_frflags = _ida_allins.RISCV_frflags

RISCV_fsflags = _ida_allins.RISCV_fsflags

RISCV_la = _ida_allins.RISCV_la

RISCV_call = _ida_allins.RISCV_call

RISCV_tail = _ida_allins.RISCV_tail

RISCV_jump = _ida_allins.RISCV_jump

RISCV_last = _ida_allins.RISCV_last

RL78_null = _ida_allins.RL78_null

RL78_subw = _ida_allins.RL78_subw

RL78_movw = _ida_allins.RL78_movw

RL78_call = _ida_allins.RL78_call

RL78_clrw = _ida_allins.RL78_clrw

RL78_addw = _ida_allins.RL78_addw

RL78_ret = _ida_allins.RL78_ret

RL78_sel = _ida_allins.RL78_sel

RL78_push = _ida_allins.RL78_push

RL78_onew = _ida_allins.RL78_onew

RL78_incw = _ida_allins.RL78_incw

RL78_cmpw = _ida_allins.RL78_cmpw

RL78_bnz = _ida_allins.RL78_bnz

RL78_clrb = _ida_allins.RL78_clrb

RL78_and = _ida_allins.RL78_and

RL78_or = _ida_allins.RL78_or

RL78_br = _ida_allins.RL78_br

RL78_pop = _ida_allins.RL78_pop

RL78_cmp = _ida_allins.RL78_cmp

RL78_decw = _ida_allins.RL78_decw

RL78_inc = _ida_allins.RL78_inc

RL78_bz = _ida_allins.RL78_bz

RL78_sknz = _ida_allins.RL78_sknz

RL78_sknh = _ida_allins.RL78_sknh

RL78_skh = _ida_allins.RL78_skh

RL78_xor1 = _ida_allins.RL78_xor1

RL78_or1 = _ida_allins.RL78_or1

RL78_and1 = _ida_allins.RL78_and1

RL78_mov1 = _ida_allins.RL78_mov1

RL78_clr1 = _ida_allins.RL78_clr1

RL78_set1 = _ida_allins.RL78_set1

RL78_not1 = _ida_allins.RL78_not1

RL78_skc = _ida_allins.RL78_skc

RL78_sknc = _ida_allins.RL78_sknc

RL78_skz = _ida_allins.RL78_skz

RL78_mov = _ida_allins.RL78_mov

RL78_btclr = _ida_allins.RL78_btclr

RL78_bt = _ida_allins.RL78_bt

RL78_bf = _ida_allins.RL78_bf

RL78_shl = _ida_allins.RL78_shl

RL78_shr = _ida_allins.RL78_shr

RL78_sar = _ida_allins.RL78_sar

RL78_shlw = _ida_allins.RL78_shlw

RL78_shrw = _ida_allins.RL78_shrw

RL78_sarw = _ida_allins.RL78_sarw

RL78_bc = _ida_allins.RL78_bc

RL78_bnc = _ida_allins.RL78_bnc

RL78_bh = _ida_allins.RL78_bh

RL78_bnh = _ida_allins.RL78_bnh

RL78_add = _ida_allins.RL78_add

RL78_addc = _ida_allins.RL78_addc

RL78_sub = _ida_allins.RL78_sub

RL78_subc = _ida_allins.RL78_subc

RL78_xor = _ida_allins.RL78_xor

RL78_xch = _ida_allins.RL78_xch

RL78_dec = _ida_allins.RL78_dec

RL78_rolwc = _ida_allins.RL78_rolwc

RL78_xchw = _ida_allins.RL78_xchw

RL78_cmps = _ida_allins.RL78_cmps

RL78_movs = _ida_allins.RL78_movs

RL78_halt = _ida_allins.RL78_halt

RL78_cmp0 = _ida_allins.RL78_cmp0

RL78_mulu = _ida_allins.RL78_mulu

RL78_oneb = _ida_allins.RL78_oneb

RL78_ror = _ida_allins.RL78_ror

RL78_rol = _ida_allins.RL78_rol

RL78_rorc = _ida_allins.RL78_rorc

RL78_rolc = _ida_allins.RL78_rolc

RL78_brk = _ida_allins.RL78_brk

RL78_retb = _ida_allins.RL78_retb

RL78_reti = _ida_allins.RL78_reti

RL78_stop = _ida_allins.RL78_stop

RL78_nop = _ida_allins.RL78_nop

RL78_callt = _ida_allins.RL78_callt

RL78_mulhu = _ida_allins.RL78_mulhu

RL78_mulh = _ida_allins.RL78_mulh

RL78_divhu = _ida_allins.RL78_divhu

RL78_divwu = _ida_allins.RL78_divwu

RL78_machu = _ida_allins.RL78_machu

RL78_mach = _ida_allins.RL78_mach

RL78_last = _ida_allins.RL78_last

RX_null = _ida_allins.RX_null

RX_abs = _ida_allins.RX_abs

RX_adc = _ida_allins.RX_adc

RX_add = _ida_allins.RX_add

RX_and = _ida_allins.RX_and

RX_bra = _ida_allins.RX_bra

RX_brk = _ida_allins.RX_brk

RX_bclr = _ida_allins.RX_bclr

RX_bfmov = _ida_allins.RX_bfmov

RX_bfmovz = _ida_allins.RX_bfmovz

RX_beq = _ida_allins.RX_beq

RX_bne = _ida_allins.RX_bne

RX_bgeu = _ida_allins.RX_bgeu

RX_bltu = _ida_allins.RX_bltu

RX_bgtu = _ida_allins.RX_bgtu

RX_bleu = _ida_allins.RX_bleu

RX_bpz = _ida_allins.RX_bpz

RX_bn = _ida_allins.RX_bn

RX_bge = _ida_allins.RX_bge

RX_blt = _ida_allins.RX_blt

RX_bgt = _ida_allins.RX_bgt

RX_ble = _ida_allins.RX_ble

RX_bo = _ida_allins.RX_bo

RX_bno = _ida_allins.RX_bno

RX_bmeq = _ida_allins.RX_bmeq

RX_bmne = _ida_allins.RX_bmne

RX_bmgeu = _ida_allins.RX_bmgeu

RX_bmltu = _ida_allins.RX_bmltu

RX_bmgtu = _ida_allins.RX_bmgtu

RX_bmleu = _ida_allins.RX_bmleu

RX_bmpz = _ida_allins.RX_bmpz

RX_bmn = _ida_allins.RX_bmn

RX_bmge = _ida_allins.RX_bmge

RX_bmlt = _ida_allins.RX_bmlt

RX_bmgt = _ida_allins.RX_bmgt

RX_bmle = _ida_allins.RX_bmle

RX_bmo = _ida_allins.RX_bmo

RX_bmno = _ida_allins.RX_bmno

RX_bnot = _ida_allins.RX_bnot

RX_bset = _ida_allins.RX_bset

RX_bsr = _ida_allins.RX_bsr

RX_btst = _ida_allins.RX_btst

RX_clrpsw = _ida_allins.RX_clrpsw

RX_cmp = _ida_allins.RX_cmp

RX_div = _ida_allins.RX_div

RX_divu = _ida_allins.RX_divu

RX_emaca = _ida_allins.RX_emaca

RX_emsba = _ida_allins.RX_emsba

RX_emula = _ida_allins.RX_emula

RX_emul = _ida_allins.RX_emul

RX_emulu = _ida_allins.RX_emulu

RX_fadd = _ida_allins.RX_fadd

RX_fcmp = _ida_allins.RX_fcmp

RX_fdiv = _ida_allins.RX_fdiv

RX_fmul = _ida_allins.RX_fmul

RX_fsqrt = _ida_allins.RX_fsqrt

RX_fsub = _ida_allins.RX_fsub

RX_ftoi = _ida_allins.RX_ftoi

RX_ftou = _ida_allins.RX_ftou

RX_int = _ida_allins.RX_int

RX_itof = _ida_allins.RX_itof

RX_jmp = _ida_allins.RX_jmp

RX_jsr = _ida_allins.RX_jsr

RX_machi = _ida_allins.RX_machi

RX_maclo = _ida_allins.RX_maclo

RX_maclh = _ida_allins.RX_maclh

RX_max = _ida_allins.RX_max

RX_min = _ida_allins.RX_min

RX_mov = _ida_allins.RX_mov

RX_movco = _ida_allins.RX_movco

RX_movli = _ida_allins.RX_movli

RX_movu = _ida_allins.RX_movu

RX_msbhi = _ida_allins.RX_msbhi

RX_msblo = _ida_allins.RX_msblo

RX_msblh = _ida_allins.RX_msblh

RX_mul = _ida_allins.RX_mul

RX_mulhi = _ida_allins.RX_mulhi

RX_mullo = _ida_allins.RX_mullo

RX_mullh = _ida_allins.RX_mullh

RX_mvfachi = _ida_allins.RX_mvfachi

RX_mvfaclo = _ida_allins.RX_mvfaclo

RX_mvfacmi = _ida_allins.RX_mvfacmi

RX_mvfacgu = _ida_allins.RX_mvfacgu

RX_mvfc = _ida_allins.RX_mvfc

RX_mvtacgu = _ida_allins.RX_mvtacgu

RX_mvtachi = _ida_allins.RX_mvtachi

RX_mvtaclo = _ida_allins.RX_mvtaclo

RX_mvtc = _ida_allins.RX_mvtc

RX_mvtipl = _ida_allins.RX_mvtipl

RX_neg = _ida_allins.RX_neg

RX_nop = _ida_allins.RX_nop

RX_not = _ida_allins.RX_not

RX_or = _ida_allins.RX_or

RX_pop = _ida_allins.RX_pop

RX_popc = _ida_allins.RX_popc

RX_popm = _ida_allins.RX_popm

RX_push = _ida_allins.RX_push

RX_pushc = _ida_allins.RX_pushc

RX_pushm = _ida_allins.RX_pushm

RX_racl = _ida_allins.RX_racl

RX_rdacl = _ida_allins.RX_rdacl

RX_racw = _ida_allins.RX_racw

RX_rdacw = _ida_allins.RX_rdacw

RX_revl = _ida_allins.RX_revl

RX_revw = _ida_allins.RX_revw

RX_rmpa = _ida_allins.RX_rmpa

RX_rolc = _ida_allins.RX_rolc

RX_rorc = _ida_allins.RX_rorc

RX_rotl = _ida_allins.RX_rotl

RX_rotr = _ida_allins.RX_rotr

RX_round = _ida_allins.RX_round

RX_rstr = _ida_allins.RX_rstr

RX_rte = _ida_allins.RX_rte

RX_rtfi = _ida_allins.RX_rtfi

RX_rts = _ida_allins.RX_rts

RX_rtsd = _ida_allins.RX_rtsd

RX_sat = _ida_allins.RX_sat

RX_satr = _ida_allins.RX_satr

RX_save = _ida_allins.RX_save

RX_sbb = _ida_allins.RX_sbb

RX_sceq = _ida_allins.RX_sceq

RX_scne = _ida_allins.RX_scne

RX_scgeu = _ida_allins.RX_scgeu

RX_scltu = _ida_allins.RX_scltu

RX_scgtu = _ida_allins.RX_scgtu

RX_scleu = _ida_allins.RX_scleu

RX_scpz = _ida_allins.RX_scpz

RX_scn = _ida_allins.RX_scn

RX_scge = _ida_allins.RX_scge

RX_sclt = _ida_allins.RX_sclt

RX_scgt = _ida_allins.RX_scgt

RX_scle = _ida_allins.RX_scle

RX_sco = _ida_allins.RX_sco

RX_scno = _ida_allins.RX_scno

RX_scmpu = _ida_allins.RX_scmpu

RX_setpsw = _ida_allins.RX_setpsw

RX_shar = _ida_allins.RX_shar

RX_shll = _ida_allins.RX_shll

RX_shlr = _ida_allins.RX_shlr

RX_smovb = _ida_allins.RX_smovb

RX_smovf = _ida_allins.RX_smovf

RX_smovu = _ida_allins.RX_smovu

RX_sstr = _ida_allins.RX_sstr

RX_stnz = _ida_allins.RX_stnz

RX_stz = _ida_allins.RX_stz

RX_sub = _ida_allins.RX_sub

RX_suntil = _ida_allins.RX_suntil

RX_swhile = _ida_allins.RX_swhile

RX_tst = _ida_allins.RX_tst

RX_utof = _ida_allins.RX_utof

RX_wait = _ida_allins.RX_wait

RX_xchg = _ida_allins.RX_xchg

RX_xor = _ida_allins.RX_xor

RX_dabs = _ida_allins.RX_dabs

RX_dadd = _ida_allins.RX_dadd

RX_dcmpun = _ida_allins.RX_dcmpun

RX_dcmpeq = _ida_allins.RX_dcmpeq

RX_dcmplt = _ida_allins.RX_dcmplt

RX_dcmple = _ida_allins.RX_dcmple

RX_ddiv = _ida_allins.RX_ddiv

RX_dmov = _ida_allins.RX_dmov

RX_dmul = _ida_allins.RX_dmul

RX_dneg = _ida_allins.RX_dneg

RX_dpopm = _ida_allins.RX_dpopm

RX_dpushm = _ida_allins.RX_dpushm

RX_dround = _ida_allins.RX_dround

RX_dsqrt = _ida_allins.RX_dsqrt

RX_dsub = _ida_allins.RX_dsub

RX_dtof = _ida_allins.RX_dtof

RX_dtoi = _ida_allins.RX_dtoi

RX_dtou = _ida_allins.RX_dtou

RX_ftod = _ida_allins.RX_ftod

RX_itod = _ida_allins.RX_itod

RX_mvfdc = _ida_allins.RX_mvfdc

RX_mvfdr = _ida_allins.RX_mvfdr

RX_mvtdc = _ida_allins.RX_mvtdc

RX_utod = _ida_allins.RX_utod

RX_last = _ida_allins.RX_last

XTENSA_null = _ida_allins.XTENSA_null

XTENSA_abs = _ida_allins.XTENSA_abs

XTENSA_add = _ida_allins.XTENSA_add

XTENSA_addi = _ida_allins.XTENSA_addi

XTENSA_addmi = _ida_allins.XTENSA_addmi

XTENSA_addx2 = _ida_allins.XTENSA_addx2

XTENSA_addx4 = _ida_allins.XTENSA_addx4

XTENSA_addx8 = _ida_allins.XTENSA_addx8

XTENSA_and = _ida_allins.XTENSA_and

XTENSA_ball = _ida_allins.XTENSA_ball

XTENSA_bany = _ida_allins.XTENSA_bany

XTENSA_bbc = _ida_allins.XTENSA_bbc

XTENSA_bbs = _ida_allins.XTENSA_bbs

XTENSA_bbci = _ida_allins.XTENSA_bbci

XTENSA_bbsi = _ida_allins.XTENSA_bbsi

XTENSA_beq = _ida_allins.XTENSA_beq

XTENSA_beqi = _ida_allins.XTENSA_beqi

XTENSA_beqz = _ida_allins.XTENSA_beqz

XTENSA_bge = _ida_allins.XTENSA_bge

XTENSA_bgei = _ida_allins.XTENSA_bgei

XTENSA_bgeu = _ida_allins.XTENSA_bgeu

XTENSA_bgeui = _ida_allins.XTENSA_bgeui

XTENSA_bgez = _ida_allins.XTENSA_bgez

XTENSA_blt = _ida_allins.XTENSA_blt

XTENSA_blti = _ida_allins.XTENSA_blti

XTENSA_bltu = _ida_allins.XTENSA_bltu

XTENSA_bltui = _ida_allins.XTENSA_bltui

XTENSA_bltz = _ida_allins.XTENSA_bltz

XTENSA_bnall = _ida_allins.XTENSA_bnall

XTENSA_bnone = _ida_allins.XTENSA_bnone

XTENSA_bne = _ida_allins.XTENSA_bne

XTENSA_bnei = _ida_allins.XTENSA_bnei

XTENSA_bnez = _ida_allins.XTENSA_bnez

XTENSA_break = _ida_allins.XTENSA_break

XTENSA_call0 = _ida_allins.XTENSA_call0

XTENSA_call4 = _ida_allins.XTENSA_call4

XTENSA_call8 = _ida_allins.XTENSA_call8

XTENSA_call12 = _ida_allins.XTENSA_call12

XTENSA_callx0 = _ida_allins.XTENSA_callx0

XTENSA_callx4 = _ida_allins.XTENSA_callx4

XTENSA_callx8 = _ida_allins.XTENSA_callx8

XTENSA_callx12 = _ida_allins.XTENSA_callx12

XTENSA_dsync = _ida_allins.XTENSA_dsync

XTENSA_entry = _ida_allins.XTENSA_entry

XTENSA_esync = _ida_allins.XTENSA_esync

XTENSA_excw = _ida_allins.XTENSA_excw

XTENSA_extui = _ida_allins.XTENSA_extui

XTENSA_extw = _ida_allins.XTENSA_extw

XTENSA_isync = _ida_allins.XTENSA_isync

XTENSA_j = _ida_allins.XTENSA_j

XTENSA_jx = _ida_allins.XTENSA_jx

XTENSA_loop = _ida_allins.XTENSA_loop

XTENSA_loopgtz = _ida_allins.XTENSA_loopgtz

XTENSA_loopnez = _ida_allins.XTENSA_loopnez

XTENSA_lsi = _ida_allins.XTENSA_lsi

XTENSA_lsx = _ida_allins.XTENSA_lsx

XTENSA_l8ui = _ida_allins.XTENSA_l8ui

XTENSA_l16si = _ida_allins.XTENSA_l16si

XTENSA_l16ui = _ida_allins.XTENSA_l16ui

XTENSA_l32i = _ida_allins.XTENSA_l32i

XTENSA_l32r = _ida_allins.XTENSA_l32r

XTENSA_max = _ida_allins.XTENSA_max

XTENSA_maxu = _ida_allins.XTENSA_maxu

XTENSA_memw = _ida_allins.XTENSA_memw

XTENSA_min = _ida_allins.XTENSA_min

XTENSA_minu = _ida_allins.XTENSA_minu

XTENSA_mov = _ida_allins.XTENSA_mov

XTENSA_moveqz = _ida_allins.XTENSA_moveqz

XTENSA_movgez = _ida_allins.XTENSA_movgez

XTENSA_movi = _ida_allins.XTENSA_movi

XTENSA_movltz = _ida_allins.XTENSA_movltz

XTENSA_movnez = _ida_allins.XTENSA_movnez

XTENSA_mul16s = _ida_allins.XTENSA_mul16s

XTENSA_mul16u = _ida_allins.XTENSA_mul16u

XTENSA_mull = _ida_allins.XTENSA_mull

XTENSA_neg = _ida_allins.XTENSA_neg

XTENSA_nsa = _ida_allins.XTENSA_nsa

XTENSA_nsau = _ida_allins.XTENSA_nsau

XTENSA_nop = _ida_allins.XTENSA_nop

XTENSA_or = _ida_allins.XTENSA_or

XTENSA_ret = _ida_allins.XTENSA_ret

XTENSA_retw = _ida_allins.XTENSA_retw

XTENSA_rfe = _ida_allins.XTENSA_rfe

XTENSA_rfi = _ida_allins.XTENSA_rfi

XTENSA_rsil = _ida_allins.XTENSA_rsil

XTENSA_rsr = _ida_allins.XTENSA_rsr

XTENSA_rsync = _ida_allins.XTENSA_rsync

XTENSA_s8i = _ida_allins.XTENSA_s8i

XTENSA_s16i = _ida_allins.XTENSA_s16i

XTENSA_s32i = _ida_allins.XTENSA_s32i

XTENSA_s32ri = _ida_allins.XTENSA_s32ri

XTENSA_sext = _ida_allins.XTENSA_sext

XTENSA_sll = _ida_allins.XTENSA_sll

XTENSA_slli = _ida_allins.XTENSA_slli

XTENSA_sra = _ida_allins.XTENSA_sra

XTENSA_srai = _ida_allins.XTENSA_srai

XTENSA_src = _ida_allins.XTENSA_src

XTENSA_srl = _ida_allins.XTENSA_srl

XTENSA_srli = _ida_allins.XTENSA_srli

XTENSA_ssa8b = _ida_allins.XTENSA_ssa8b

XTENSA_ssa8l = _ida_allins.XTENSA_ssa8l

XTENSA_ssai = _ida_allins.XTENSA_ssai

XTENSA_ssl = _ida_allins.XTENSA_ssl

XTENSA_ssr = _ida_allins.XTENSA_ssr

XTENSA_sub = _ida_allins.XTENSA_sub

XTENSA_subx2 = _ida_allins.XTENSA_subx2

XTENSA_subx4 = _ida_allins.XTENSA_subx4

XTENSA_subx8 = _ida_allins.XTENSA_subx8

XTENSA_waiti = _ida_allins.XTENSA_waiti

XTENSA_wdtlb = _ida_allins.XTENSA_wdtlb

XTENSA_witlb = _ida_allins.XTENSA_witlb

XTENSA_wsr = _ida_allins.XTENSA_wsr

XTENSA_xor = _ida_allins.XTENSA_xor

XTENSA_xsr = _ida_allins.XTENSA_xsr

XTENSA_last = _ida_allins.XTENSA_last




