"""
ml_classifier.py  v2
────────────────────
Rich ML ensemble for distinguishing legitimate high-entropy data from
deliberate wipe patterns — vectorised batch processing for speed.

═══════════════════════════════════════════════════════════════════════
THE CORE PROBLEM
═══════════════════════════════════════════════════════════════════════
AES-256-CBC, DEFLATE/ZLIB, JPEG/H.264, and OpenSSL outputs ALL produce
Shannon entropy ≥ 7.5 bits/byte AND near-flat byte distributions —
identical measurements to a CSPRNG-based wipe tool (shred, DBAN, sdelete).

The rule-based classifier uses entropy + distribution uniformity.
At high-entropy, these two signals are INSUFFICIENT to separate classes.
We need 30 additional signals that exploit how CSPRNG output differs
from structured entropy at a deeper level.

═══════════════════════════════════════════════════════════════════════
FEATURE ENGINEERING — 30 DIMENSIONS
═══════════════════════════════════════════════════════════════════════
Group 1 — Distribution Shape (9)  F01-F09
Group 2 — Serial Structure (6)    F10-F15
Group 3 — Spectral/Frequency (4)  F16-F19
Group 4 — Block Structure (6)     F20-F25
Group 5 — Entropy Sub-block (5)   F26-F30

═══════════════════════════════════════════════════════════════════════
ENSEMBLE ARCHITECTURE
═══════════════════════════════════════════════════════════════════════
  RandomForestClassifier(200 trees)
  ExtraTreesClassifier(200 trees)
  GradientBoostingClassifier(150 trees)
  IsolationForest(200 trees) — anomaly gate

Final decision: argmax(mean(RF_proba, ET_proba, GB_proba))
Override threshold: 0.70 ensemble confidence

═══════════════════════════════════════════════════════════════════════
TRAINING DATASET — ~15,000 SYNTHETIC SAMPLES
═══════════════════════════════════════════════════════════════════════
  Class 0  CSPRNG_WIPE    os.urandom() + PRNG-seeded
  Class 1  NORMAL         ZLIB/BZ2 compressed, AES-CBC sim, JPEG sim, mixed binary
  Class 2  ZERO_WIPE      0x00 fill ± noise
  Class 3  FF_WIPE        0xFF fill ± noise
  Class 4  MULTI_PASS     Gutmann/DoD pattern wipes
"""

import bz2
import hashlib
import math
import os
import random
import struct
import time
import zlib
import joblib
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Tuple

try:
    import numpy as np
    _NP = True
except ImportError:
    _NP = False
    print("[MLClassifier] WARNING: numpy not available. pip install numpy")

try:
    from sklearn.ensemble import (
        RandomForestClassifier,
        ExtraTreesClassifier,
        GradientBoostingClassifier,
        IsolationForest,
    )
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score
    _SKLEARN = True
except ImportError:
    _SKLEARN = False
    print("[MLClassifier] WARNING: scikit-learn not available. pip install scikit-learn")


# ─────────────────────────────────────────────────────────────────────────────
# RESULT
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MLResult:
    block_id:       int
    offset:         int
    ml_label:       str
    ml_confidence:  float
    base_label:     str
    final_label:    str
    is_suspicious:  bool
    entropy:        float
    anomaly_score:  float
    feature_vector: list
    ml_override:    bool
    ensemble_votes: dict


_SUSPICIOUS_LABELS = {
    "RANDOM_WIPE", "ZERO_WIPE", "FF_WIPE", "MULTI_PASS",
    "LIKELY_ZERO_WIPE", "LIKELY_FF_WIPE", "LOW_ENTROPY_SUSPECT",
}

_LABEL_MAP = {0: "RANDOM_WIPE", 1: "NORMAL", 2: "ZERO_WIPE", 3: "FF_WIPE", 4: "MULTI_PASS"}

MAGIC_BYTES = frozenset([0x50,0x4B,0x1F,0x8B,0xFF,0xD8,0x89,0x50,0x25,0x50,
                          0x7F,0x45,0x4D,0x5A,0x52,0x61,0xFD,0x37,0x42,0x5A])


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION — 30 DIMENSIONS
# ─────────────────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data: return 0.0
    if _NP:
        a = np.frombuffer(data, dtype=np.uint8)
        c = np.bincount(a, minlength=256); f = c[c>0]/len(data)
        return float(-np.sum(f * np.log2(f)))
    counts = {}
    for b in data: counts[b] = counts.get(b,0)+1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())


def extract_features(data: bytes) -> list:
    n = len(data)
    if n == 0: return [0.0]*30

    if _NP:
        arr = np.frombuffer(data, dtype=np.uint8)
        cnts = np.bincount(arr, minlength=256)
        freq = cnts / n
    else:
        raw = [0]*256
        for b in data: raw[b]+=1
        freq = [c/n for c in raw]
        cnts = raw

    # ── G1: Distribution shape ────────────────────────────────────────────
    if _NP:
        nz = freq[freq>0]; h = float(-np.sum(nz*np.log2(nz))) if len(nz)>0 else 0.0
    else:
        h = -sum(f*math.log2(f) for f in freq if f>0)
    f01 = h/8.0

    exp = 1.0/256
    if _NP:
        f02 = min(float(np.sqrt(np.mean((freq-exp)**2)))/0.06, 1.0)
        exp_c = n/256.0
        f03 = min(float(np.sum((cnts-exp_c)**2/exp_c))/(n*4), 1.0)
        nzm = freq>0; f04 = min(abs(float(np.sum(freq[nzm]*np.log2(freq[nzm]*256))))/8.0, 1.0)
        f05 = min(float(np.sum(np.sort(freq)[-8:]))/0.25, 1.0)
        f06 = min(float(np.sum(np.sort(freq)[:8]))/0.03, 1.0)
        f07 = float(np.max(freq))
        f08 = float(np.sum(freq>0))/256
    else:
        f02 = min(math.sqrt(sum((f-exp)**2 for f in freq)/256)/0.06, 1.0)
        exp_c = n/256.0
        f03 = min(sum((c*n-exp_c)**2/exp_c for c in freq)/(n*4), 1.0)
        f04 = min(abs(sum(f*math.log2(f*256) for f in freq if f>0))/8.0, 1.0)
        sf = sorted(freq)
        f05 = min(sum(sf[-8:])/0.25, 1.0)
        f06 = min(sum(sf[:8])/0.03, 1.0)
        f07 = max(freq)
        f08 = sum(1 for f in freq if f>0)/256

    smp = data[:512]
    f09 = (max(smp)-min(smp))/255.0 if smp else 0.0

    # ── G2: Serial structure ──────────────────────────────────────────────
    samp = min(n, 1024); d = data[:samp]

    def _corr(xs, ys):
        if not _NP:
            mx,my = sum(xs)/len(xs),sum(ys)/len(ys)
            num = sum((xs[i]-mx)*(ys[i]-my) for i in range(len(xs)))
            den = math.sqrt(sum((v-mx)**2 for v in xs)*sum((v-my)**2 for v in ys))
            return abs(num/den) if den>0 else 0.0
        xn,yn = np.array(xs,dtype=float),np.array(ys,dtype=float)
        xm,ym = xn.mean(),yn.mean()
        num = float(np.sum((xn-xm)*(yn-ym)))
        den = float(np.sqrt(np.sum((xn-xm)**2)*np.sum((yn-ym)**2)))
        return abs(num/den) if den>0 else 0.0

    if samp>=4:
        f10 = _corr([d[i] for i in range(samp-1)],[d[i+1] for i in range(samp-1)])
    else: f10=0.0
    if samp>=6:
        f11 = _corr([d[i] for i in range(samp-2)],[d[i+2] for i in range(samp-2)])
    else: f11=0.0
    f12 = min(sum(1 for i in range(samp-1) if d[i]==d[i+1])/(samp-1)/0.05, 1.0) if samp>=2 else 0.0
    f13 = min(sum(1 for i in range(samp-2) if d[i]==d[i+1]==d[i+2])/(samp-2)/0.01, 1.0) if samp>=3 else 0.0

    runs=[]; rlen=1
    for i in range(1,samp):
        if d[i]==d[i-1]: rlen+=1
        else: runs.append(rlen); rlen=1
    runs.append(rlen)
    f14 = min((sum(runs)/len(runs) if runs else 1.0)/8.0, 1.0)
    f15 = min((max(runs) if runs else 1)/50.0, 1.0)

    # ── G3: Spectral ─────────────────────────────────────────────────────
    sp=min(n,512); sig=[b/255.0 for b in data[:sp]]
    bk=16; bs=max(sp//bk,1)
    buckets=[]
    for i in range(bk):
        ch=sig[i*bs:(i+1)*bs]; e=sum(x*x for x in ch)/max(len(ch),1)+1e-10; buckets.append(e)
    gm=math.exp(sum(math.log(e) for e in buckets)/len(buckets))
    am=sum(buckets)/len(buckets)
    f16=min(gm/am,1.0)
    te=sum(buckets)+1e-10
    f17=sum(buckets[:4])/te; f18=sum(buckets[4:12])/te; f19=sum(buckets[12:])/te

    # ── G4: Block structure ───────────────────────────────────────────────
    mxr=cr=0
    for b in data[:512]:
        if 0x20<=b<=0x7E: cr+=1; mxr=max(mxr,cr)
        else: cr=0
    f20=min(mxr/128.0,1.0)
    f21=1.0 if bool(set(data[:16])&MAGIC_BYTES) else 0.0
    f22=float(freq[0]) if not _NP else float(freq[0])
    f23=float(freq[255]) if not _NP else float(freq[255])
    if _NP:
        f24=min(float(np.sum(freq[0:32]))/0.125/3,1.0)
        f25=min(float(np.sum(freq[128:160]))/0.125/3,1.0)
    else:
        f24=min(sum(freq[0:32])/0.125/3,1.0)
        f25=min(sum(freq[128:160])/0.125/3,1.0)

    # ── G5: Entropy sub-blocks ────────────────────────────────────────────
    f26=_entropy(data[:128])/8.0
    f27=_entropy(data[-128:])/8.0 if n>=128 else f26
    f28=abs(f26-f27)
    f29=_entropy(data[::2])/8.0
    f30=_entropy(data[1::2])/8.0

    return [f01,f02,f03,f04,f05,f06,f07,f08,f09,f10,
            f11,f12,f13,f14,f15,f16,f17,f18,f19,f20,
            f21,f22,f23,f24,f25,f26,f27,f28,f29,f30]


# ─────────────────────────────────────────────────────────────────────────────
# TRAINING DATA
# ─────────────────────────────────────────────────────────────────────────────

def _aes_sim(bs):
    key=bytes([random.randint(0,255) for _ in range(32)])
    d=bytearray(os.urandom(bs))
    for i in range(0,bs,16):
        d[i]=(d[i]^key[i%32])&0xFF
        if i>=16: d[i]=(d[i]^d[i-16])&0xFF
    return bytes(d)

def _jpeg_sim(bs):
    d=bytearray(os.urandom(bs))
    for i in range(0,bs-1,2):
        if d[i]==0xFF: d[i+1]=random.choice([0x00,random.randint(0xC0,0xFE)])
    if bs>=64:
        for i in range(0,32,2): d[i]=random.randint(1,64)
    return bytes(d)

def _ntfs_sim(bs):
    d=bytearray(bs); d[0:4]=b'FILE'
    if bs>48: struct.pack_into('<HH',d,4,48,3)
    pos=48
    for attr in [0x10,0x30,0x80]:
        if pos+40>bs: break
        al=48
        struct.pack_into('<HH',d,pos,attr,al)
        for j in range(8,al): d[pos+j]=random.randint(0,255)
        pos+=al
    return bytes(d)


def _generate_training_data(n_per_class=1500):
    BLOCK=512; X,y=[],[]
    rng=random.Random(42)

    # Class 0: CSPRNG wipe
    for _ in range(n_per_class):
        X.append(extract_features(os.urandom(BLOCK))); y.append(0)
    # Class 0b: seeded PRNG wipe
    for _ in range(n_per_class//3):
        r=random.Random(rng.randint(0,2**32))
        X.append(extract_features(bytes([r.randint(0,255) for _ in range(BLOCK)]))); y.append(0)

    # Class 1: ZLIB compressed
    for _ in range(n_per_class):
        ct=rng.randint(0,2)
        if ct==0: raw=bytes([rng.randint(0x20,0x7E) for _ in range(BLOCK*8)])
        elif ct==1: raw=bytes([rng.randint(0,255) for _ in range(BLOCK*3)])
        else:
            pat=bytes([rng.randint(0,255) for _ in range(rng.randint(4,64))])
            raw=(pat*(BLOCK*4//len(pat)+1))[:BLOCK*4]
        try:
            c=zlib.compress(raw,level=rng.randint(6,9))
            block=(c*(BLOCK//len(c)+2))[:BLOCK]
        except: block=os.urandom(BLOCK)
        X.append(extract_features(block)); y.append(1)

    # Class 1b: BZ2
    for _ in range(n_per_class//2):
        raw=bytes([rng.randint(0x20,0x7E) for _ in range(BLOCK*6)])
        try:
            c=bz2.compress(raw,compresslevel=9)
            block=(c*(BLOCK//max(len(c),1)+2))[:BLOCK]
        except: block=os.urandom(BLOCK)
        X.append(extract_features(block)); y.append(1)

    # Class 1c: AES-CBC sim
    for _ in range(n_per_class):
        X.append(extract_features(_aes_sim(BLOCK))); y.append(1)

    # Class 1d: JPEG sim
    for _ in range(n_per_class//2):
        X.append(extract_features(_jpeg_sim(BLOCK))); y.append(1)

    # Class 1e: mixed binary
    for _ in range(n_per_class//2):
        hdr=bytes([rng.randint(0,0x7F) for _ in range(int(BLOCK*0.4))])
        payload=os.urandom(BLOCK-len(hdr))
        X.append(extract_features(hdr+payload)); y.append(1)

    # Class 2: ZERO_WIPE
    for _ in range(n_per_class):
        d=bytearray(BLOCK)
        for _ in range(rng.randint(0,8)): d[rng.randint(0,BLOCK-1)]=rng.randint(1,255)
        X.append(extract_features(bytes(d))); y.append(2)

    # Class 3: FF_WIPE
    for _ in range(n_per_class):
        d=bytearray([0xFF]*BLOCK)
        for _ in range(rng.randint(0,8)): d[rng.randint(0,BLOCK-1)]=rng.randint(0,0xFE)
        X.append(extract_features(bytes(d))); y.append(3)

    # Class 4: Pattern wipes (Gutmann/DoD)
    PATS=[[0x55,0xAA],[0x92,0x49,0x24],[0x6D,0xB6,0xDB],[0x00],[0xFF],
          [0xAA,0x55,0xAA,0x55],[0x27,0xC4,0xDB],[0xB4,0x24,0x24]]
    for _ in range(n_per_class):
        pat=rng.choice(PATS)
        d=bytearray((pat*(BLOCK//len(pat)+1))[:BLOCK])
        for _ in range(rng.randint(0,4)): d[rng.randint(0,BLOCK-1)]^=rng.randint(1,15)
        X.append(extract_features(bytes(d))); y.append(4)

    # Class 5: NTFS metadata (maps to NORMAL)
    for _ in range(n_per_class//3):
        X.append(extract_features(_ntfs_sim(BLOCK))); y.append(1)

    return X, y


# ─────────────────────────────────────────────────────────────────────────────
# ML CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class MLClassifier:
    """
    4-model ensemble: RandomForest(200) + ExtraTrees(200) +
    GradientBoosting(150) + IsolationForest(200).
    Batch predict in single matrix operation — no serial seeking.
    """

    def __init__(self):
        self._trained=False; self._rf=self._et=self._gb=self._iso=self._scaler=None
        self.model_version="untrained"; self.training_time=0.0
        self.cv_scores={}; self.n_features=30; self.n_training_samples=0
        if not _SKLEARN: return
        self._train()

    def _train(self):
        t0=time.time()
        print("[MLClassifier] Generating ~15,000 training samples…")
        X,y=_generate_training_data(n_per_class=1500)
        self.n_training_samples=len(X)
        dist={i:y.count(i) for i in set(y)}
        print(f"[MLClassifier] {self.n_training_samples} samples. Labels: {dist}")

        self._scaler=StandardScaler()
        Xs=self._scaler.fit_transform(X)

        print("[MLClassifier] Training RandomForest(200)…")
        self._rf=RandomForestClassifier(n_estimators=200,max_depth=15,min_samples_leaf=2,
            max_features="sqrt",class_weight="balanced",n_jobs=-1,random_state=42)
        self._rf.fit(Xs,y)

        print("[MLClassifier] Training ExtraTrees(200)…")
        self._et=ExtraTreesClassifier(n_estimators=200,max_depth=15,min_samples_leaf=2,
            max_features="sqrt",class_weight="balanced",n_jobs=-1,random_state=7)
        self._et.fit(Xs,y)

        print("[MLClassifier] Training GradientBoosting(150)…")
        self._gb=GradientBoostingClassifier(n_estimators=150,learning_rate=0.08,
            max_depth=6,subsample=0.8,random_state=13)
        self._gb.fit(Xs,y)

        print("[MLClassifier] Training IsolationForest(200)…")
        self._iso=IsolationForest(n_estimators=200,contamination=0.05,n_jobs=-1,random_state=42)
        self._iso.fit(Xs)

        print("[MLClassifier] 5-fold cross-validation…")
        cv=cross_val_score(self._rf,Xs,y,cv=5,scoring="f1_macro",n_jobs=-1)
        self.cv_scores={"f1_macro_mean":round(float(cv.mean()),4),"f1_macro_std":round(float(cv.std()),4)}
        print(f"[MLClassifier] CV F1-macro: {cv.mean():.4f} ± {cv.std():.4f}")

        self.training_time=time.time()-t0
        sig=f"{self.n_training_samples}:{cv.mean():.6f}"
        self.model_version="v2-"+hashlib.sha256(sig.encode()).hexdigest()[:12]
        self._trained=True
        print(f"[MLClassifier] ✓ Done in {self.training_time:.1f}s. Model: {self.model_version}")

    def batch_classify_raw(self, block_ids, offsets, data_list, base_results,
                            progress_cb=None):
        """
        VECTORISED batch classify — extracts ALL features first,
        then runs ONE predict_proba call across all 3 models.
        No serial seeking. Fast for 50k+ blocks.
        """
        if not self._trained or not _SKLEARN:
            return [self._pt(bid,off,base) for bid,off,base in zip(block_ids,offsets,base_results)]
        n=len(data_list)
        if n==0: return []

        # Extract all features
        if progress_cb: progress_cb(0,n)
        feats=[extract_features(d) for d in data_list]
        if progress_cb: progress_cb(n//2,n)

        # Scale + predict in bulk
        X=self._scaler.transform(feats)
        rf_p=self._rf.predict_proba(X)
        et_p=self._et.predict_proba(X)
        gb_p=self._gb.predict_proba(X)
        iso_s=self._iso.score_samples(X)

        if _NP:
            avg=((rf_p+et_p+gb_p)/3.0)
            preds=avg.argmax(axis=1); confs=avg.max(axis=1)
        else:
            avg=[[(rf_p[i][j]+et_p[i][j]+gb_p[i][j])/3 for j in range(5)] for i in range(n)]
            preds=[max(range(5),key=lambda j:avg[i][j]) for i in range(n)]
            confs=[avg[i][preds[i]] for i in range(n)]

        results=[]
        for i in range(n):
            bid=block_ids[i]; off=offsets[i]; base=base_results[i]
            ml_class=int(preds[i]); ml_conf=float(confs[i])
            ml_label=_LABEL_MAP[ml_class]; anom=float(iso_s[i])
            bl=base.wipe_type; override=False

            if ml_conf>=0.70 and ml_label!=bl:
                mat=((bl=="RANDOM_WIPE" and ml_label=="NORMAL") or
                     (bl=="NORMAL" and ml_label in {"RANDOM_WIPE","ZERO_WIPE","FF_WIPE","MULTI_PASS"}) or
                     (bl in {"LIKELY_ZERO_WIPE","LIKELY_FF_WIPE"} and ml_label=="NORMAL"))
                if mat: override=True

            if anom<-0.15 and base.entropy>=7.0 and bl=="NORMAL" and not override:
                ml_label="RANDOM_WIPE"; ml_conf=max(ml_conf,0.55); override=True

            fl=ml_label if override else bl
            results.append(MLResult(
                block_id=bid, offset=off, ml_label=ml_label, ml_confidence=ml_conf,
                base_label=bl, final_label=fl, is_suspicious=fl in _SUSPICIOUS_LABELS,
                entropy=base.entropy, anomaly_score=anom, feature_vector=feats[i],
                ml_override=override,
                ensemble_votes={"rf":_LABEL_MAP[int(rf_p[i].argmax())],"et":_LABEL_MAP[int(et_p[i].argmax())],"gb":_LABEL_MAP[int(gb_p[i].argmax())]},
            ))

        if progress_cb: progress_cb(n,n)
        return results

    def _pt(self,bid,off,base):
        return MLResult(block_id=bid,offset=off,ml_label=base.wipe_type,
            ml_confidence=base.confidence,base_label=base.wipe_type,final_label=base.wipe_type,
            is_suspicious=base.is_suspicious,entropy=base.entropy,anomaly_score=0.0,
            feature_vector=[0.0]*30,ml_override=False,ensemble_votes={})

    @property
    def is_available(self): return self._trained and _SKLEARN

    def summary(self):
        return {"model_version":self.model_version,"n_training_samples":self.n_training_samples,
                "n_features":self.n_features,"training_time_s":round(self.training_time,2),
                "cv_scores":self.cv_scores,"models":["RF-200","ET-200","GB-150","IF-200"],
                "available":self.is_available}

# ── Model cache config ────────────────────────────────────────────────────────
_MODEL_CACHE_DIR  = Path("ml_models")
_MODEL_CACHE_DIR.mkdir(exist_ok=True)

# Bump this string any time you change training params/features to force retrain
_MODEL_VERSION_KEY = "wipetrace-v1-rf200-et200-gb150-iso200"
_MODEL_CACHE_PATH  = _MODEL_CACHE_DIR / f"{_MODEL_VERSION_KEY}.joblib"

_instance: MLClassifier | None = None


def get_classifier() -> MLClassifier:
    global _instance

    # 1. Already loaded in this process — return immediately
    if _instance is not None:
        return _instance

    # 2. Cached model exists on disk — load it (~1s) instead of retraining (~200s)
    if _MODEL_CACHE_PATH.exists():
        print(f"[MLClassifier] Loading cached model: {_MODEL_CACHE_PATH}")
        try:
            _instance = joblib.load(_MODEL_CACHE_PATH)
            print(f"[MLClassifier] ✓ Loaded (version: {_instance.model_version})")
            return _instance
        except Exception as e:
            print(f"[MLClassifier] Cache load failed ({e}) — retraining…")
            _MODEL_CACHE_PATH.unlink(missing_ok=True)

    # 3. No cache — train once and save
    print("[MLClassifier] Training new model (one-time cost)…")
    _instance = MLClassifier()

    try:
        joblib.dump(_instance, _MODEL_CACHE_PATH)
        print(f"[MLClassifier] ✓ Model cached to {_MODEL_CACHE_PATH}")
    except Exception as e:
        print(f"[MLClassifier] Warning: could not save model cache: {e}")

    return _instance
