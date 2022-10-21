// a module wrapping the rest of this so it's compabitle with wasm.
// since wasm functions can't use type parameters, we fix the curve to edwards on bn254 and pass serrialized buffers to/from js

use crate::discrete_log_cards::DLCards;
use crate::BarnettSmartProtocol;
use ark_ec::ProjectiveCurve;
use ark_ed_on_bn254::{EdwardsProjective, Fr};
use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use proof_essentials::homomorphic_encryption::el_gamal;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

#[cfg(feature = "js")]
use wasm_bindgen::prelude::*;
#[cfg(feature = "js")]
use wasm_bindgen::JsError;

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "js")]
use serde_wasm_bindgen::{from_value, to_value};

use crate::discrete_log_cards::{
    Card, MaskedCard, Parameters, PlayerSecretKey, PublicKey, RevealToken, ZKProofShuffle,
};

pub type BnScalar = Fr;
pub type BnPublicKey = PublicKey<EdwardsProjective>;
pub type BnPlayerSecretKey = PlayerSecretKey<EdwardsProjective>;
pub type BnCard = Card<EdwardsProjective>;
pub type BnMaskedCard = MaskedCard<EdwardsProjective>;
pub type BnRevealToken = RevealToken<EdwardsProjective>;
pub type BnZKProofShuffle = ZKProofShuffle<EdwardsProjective>;
pub type BnParameters = Parameters<EdwardsProjective>;

pub type BnCardProtocol = DLCards<EdwardsProjective>;
pub type BnZKProofKeyOwnership = <BnCardProtocol as BarnettSmartProtocol>::ZKProofKeyOwnership;
pub type BnZKProofMasking = <BnCardProtocol as BarnettSmartProtocol>::ZKProofMasking;
pub type BnZKProofRemasking = <BnCardProtocol as BarnettSmartProtocol>::ZKProofRemasking;
pub type BnZKProofReveal = <BnCardProtocol as BarnettSmartProtocol>::ZKProofReveal;

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnPublicKeyBuf {
    pub(crate) buf: Vec<u8>,
}

impl BnPublicKeyBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnPublicKey) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnPublicKey, SerializationError> {
        BnPublicKey::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnPublicKey, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnPublicKey) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnPlayerSecretKeyBuf {
    pub(crate) buf: Vec<u8>,
}

impl BnPlayerSecretKeyBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnPlayerSecretKey) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnPlayerSecretKey, SerializationError> {
        BnPlayerSecretKey::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnPlayerSecretKey, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnPlayerSecretKey) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnCardBuf {
    pub(crate) buf: Vec<u8>,
}

impl BnCardBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnCard) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnCard, SerializationError> {
        BnCard::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnCard, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnCard) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnMaskedCardBuf {
    pub(crate) buf: Vec<u8>,
}

impl BnMaskedCardBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnMaskedCard) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnMaskedCard, SerializationError> {
        BnMaskedCard::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnMaskedCard, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnMaskedCard) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnRevealTokenBuf {
    pub(crate) buf: Vec<u8>,
}

impl BnRevealTokenBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnRevealToken) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnRevealToken, SerializationError> {
        BnRevealToken::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnRevealToken, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnRevealToken) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnZKProofShuffleBuf {
    pub(crate) buf: Vec<u8>,
}

impl BnZKProofShuffleBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnZKProofShuffle) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnZKProofShuffle, SerializationError> {
        BnZKProofShuffle::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnZKProofShuffle, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnZKProofShuffle) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnZKProofKeyOwnershipBuf {
    pub(crate) buf: Vec<u8>,
}

impl BnZKProofKeyOwnershipBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnZKProofKeyOwnership) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnZKProofKeyOwnership, SerializationError> {
        BnZKProofKeyOwnership::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnZKProofKeyOwnership, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnZKProofKeyOwnership) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnZKProofMaskingBuf {
    pub(crate) buf: Vec<u8>,
}

impl BnZKProofMaskingBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnZKProofMasking) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnZKProofMasking, SerializationError> {
        BnZKProofMasking::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnZKProofMasking, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnZKProofMasking) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnZKProofRemaskingBuf {
    pub(crate) buf: Vec<u8>,
}

impl BnZKProofRemaskingBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnZKProofRemasking) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnZKProofRemasking, SerializationError> {
        BnZKProofRemasking::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnZKProofRemasking, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnZKProofRemasking) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnZKProofRevealBuf {
    pub(crate) buf: Vec<u8>,
}

impl BnZKProofRevealBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnZKProofReveal) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnZKProofReveal, SerializationError> {
        BnZKProofReveal::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnZKProofReveal, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnZKProofReveal) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnParamsBuf {
    pub buf: Vec<u8>,
}

impl BnParamsBuf {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn serialize(item: BnParameters) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();
        item.serialize_uncompressed(&mut buf)?;
        Ok(Self { buf })
    }

    pub fn deserialize(&self) -> Result<BnParameters, SerializationError> {
        BnParameters::deserialize_uncompressed(self.buf.as_slice())
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<BnParameters, JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(val: BnParameters) -> Result<JsValue, JsError> {
        let s =
            Self::serialize(val).map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnKeypairBuf {
    pub(crate) pk: Vec<u8>,
    pub(crate) sk: Vec<u8>,
}

impl BnKeypairBuf {
    pub fn new(pk: Vec<u8>, sk: Vec<u8>) -> Self {
        Self { pk, sk }
    }

    pub fn serialize(_pk: BnPublicKey, _sk: BnPlayerSecretKey) -> Result<Self, SerializationError> {
        let mut pk = Vec::new();
        let mut sk = Vec::new();
        _pk.serialize_uncompressed(&mut pk)?;
        _sk.serialize_uncompressed(&mut sk)?;
        Ok(Self { pk, sk })
    }

    pub fn deserialize(&self) -> Result<(BnPublicKey, BnPlayerSecretKey), SerializationError> {
        let pk = BnPublicKey::deserialize_uncompressed(self.pk.as_slice())?;
        let sk = BnPlayerSecretKey::deserialize_uncompressed(self.sk.as_slice())?;
        Ok((pk, sk))
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<(BnPublicKey, BnPlayerSecretKey), JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(pk: BnPublicKey, sk: BnPlayerSecretKey) -> Result<JsValue, JsError> {
        let s = Self::serialize(pk, sk)
            .map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnMaskingOutputBuf {
    pub(crate) masked_card: Vec<u8>,
    pub(crate) proof: Vec<u8>,
}

impl BnMaskingOutputBuf {
    pub fn new(masked_card: Vec<u8>, proof: Vec<u8>) -> Self {
        Self { masked_card, proof }
    }

    pub fn serialize(
        _masked_card: BnMaskedCard,
        _proof: BnZKProofMasking,
    ) -> Result<Self, SerializationError> {
        let mut masked_card = Vec::new();
        let mut proof = Vec::new();
        _masked_card.serialize_uncompressed(&mut masked_card)?;
        _proof.serialize_uncompressed(&mut proof)?;
        Ok(Self { masked_card, proof })
    }

    pub fn deserialize(&self) -> Result<(BnMaskedCard, BnZKProofMasking), SerializationError> {
        let masked_card = BnMaskedCard::deserialize_uncompressed(self.masked_card.as_slice())?;
        let proof = BnZKProofMasking::deserialize_uncompressed(self.masked_card.as_slice())?;
        Ok((masked_card, proof))
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<(BnMaskedCard, BnZKProofMasking), JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(masked_card: BnMaskedCard, proof: BnZKProofMasking) -> Result<JsValue, JsError> {
        let s = Self::serialize(masked_card, proof)
            .map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnShuffleOutputBuf {
    pub shuffled_deck: Vec<Vec<u8>>,
    pub(crate) proof: Vec<u8>,
}

impl BnShuffleOutputBuf {
    pub fn new(shuffled_deck: Vec<Vec<u8>>, proof: Vec<u8>) -> Self {
        Self {
            shuffled_deck,
            proof,
        }
    }

    pub fn serialize(
        _shuffled_deck: Vec<BnMaskedCard>,
        _proof: BnZKProofShuffle,
    ) -> Result<Self, SerializationError> {
        let mut shuffled_deck = Vec::new();
        let mut proof = Vec::new();
        for card in _shuffled_deck {
            let mut buf = Vec::new();
            card.serialize_uncompressed(&mut buf)?;
            shuffled_deck.push(buf);
        }
        _proof.serialize(&mut proof)?;
        Ok(Self {
            shuffled_deck,
            proof,
        })
    }

    pub fn deserialize(&self) -> Result<(Vec<BnMaskedCard>, BnZKProofShuffle), SerializationError> {
        let mut shuffled_deck = Vec::new();
        for card in &self.shuffled_deck {
            shuffled_deck.push(BnMaskedCard::deserialize_uncompressed(card.as_slice())?);
        }
        let proof = BnZKProofShuffle::deserialize_uncompressed(self.proof.as_slice())?;
        Ok((shuffled_deck, proof))
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<(Vec<BnMaskedCard>, BnZKProofShuffle), JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(
        shuffled_deck: Vec<BnMaskedCard>,
        proof: BnZKProofShuffle,
    ) -> Result<JsValue, JsError> {
        let s = Self::serialize(shuffled_deck, proof)
            .map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BnRevealTokenWithProofBuf {
    pub(crate) reveal_token: Vec<u8>,
    pub(crate) proof: Vec<u8>,
}

impl BnRevealTokenWithProofBuf {
    pub fn new(reveal_token: Vec<u8>, proof: Vec<u8>) -> Self {
        Self {
            reveal_token,
            proof,
        }
    }

    pub fn serialize(
        _reveal_token: BnRevealToken,
        _proof: BnZKProofReveal,
    ) -> Result<Self, SerializationError> {
        let mut reveal_token = Vec::new();
        let mut proof = Vec::new();
        _reveal_token.serialize_uncompressed(&mut reveal_token)?;
        _proof.serialize_uncompressed(&mut proof)?;
        Ok(Self {
            reveal_token,
            proof,
        })
    }

    pub fn deserialize(&self) -> Result<(BnRevealToken, BnZKProofReveal), SerializationError> {
        let reveal_token = BnRevealToken::deserialize_uncompressed(self.reveal_token.as_slice())?;
        let proof = BnZKProofReveal::deserialize_uncompressed(self.proof.as_slice())?;
        Ok((reveal_token, proof))
    }

    #[cfg(feature = "js")]
    pub fn from_js(val: JsValue) -> Result<(BnRevealToken, BnZKProofReveal), JsError> {
        let s: Self = from_value(val).map_err(|_| JsError::new("serialization from js failed"))?;
        s.deserialize()
            .map_err(|_| JsError::new("deserialization to arkworks failed"))
    }

    #[cfg(feature = "js")]
    pub fn to_js(reveal_token: BnRevealToken, proof: BnZKProofReveal) -> Result<JsValue, JsError> {
        let s = Self::serialize(reveal_token, proof)
            .map_err(|_| JsError::new("serialization to arkworks failed"))?;
        to_value(&s).map_err(|_| JsError::new("serialization to js failed"))
    }
}

#[cfg_attr(feature = "js", wasm_bindgen)]
pub struct WasmBnDlCards;

#[cfg(feature = "js")]
#[cfg_attr(feature = "js", wasm_bindgen)]
impl WasmBnDlCards {
    #[cfg_attr(feature = "js", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self
    }

    pub fn player_keygen(params: JsValue, entropy: &[u8]) -> Result<JsValue, JsError> {
        let mut rng = StdRng::from_seed(
            entropy[0..32]
                .try_into()
                .map_err(|_| JsError::new("entropy must be >= 32 bytes"))?,
        );
        let params = BnParamsBuf::from_js(params)?;
        let (pk, sk) = BnCardProtocol::player_keygen(&mut rng, &params)
            .map_err(|_| JsError::new("failed to generate keypair"))?;
        BnKeypairBuf::to_js(pk, sk)
    }

    pub fn prove_key_ownership(
        params: JsValue,
        pk: JsValue,
        sk: JsValue,
        player_id: &str,
        entropy: &[u8],
    ) -> Result<JsValue, JsError> {
        let mut rng = StdRng::from_seed(
            entropy[0..32]
                .try_into()
                .map_err(|_| JsError::new("entropy must be >= 32 bytes"))?,
        );
        let params = BnParamsBuf::from_js(params)?;
        let pk = BnPublicKeyBuf::from_js(pk)?;
        let sk = BnPlayerSecretKeyBuf::from_js(sk)?;

        let proof =
            BnCardProtocol::prove_key_ownership(&mut rng, &params, &pk, &sk, player_id.as_bytes())
                .map_err(|_| JsError::new("failed to generate proof"))?;
        BnZKProofKeyOwnershipBuf::to_js(proof)
    }

    pub fn init_mask(
        pp: JsValue,
        shared_key: JsValue,
        original_card: JsValue,
        entropy: &[u8],
    ) -> Result<JsValue, JsError> {
        let pp = BnParamsBuf::from_js(pp)?;
        let shared_key = BnPublicKeyBuf::from_js(shared_key)?;
        let original_card = BnCardBuf::from_js(original_card)?;
        let mut rng = StdRng::from_seed(
            entropy[0..32]
                .try_into()
                .map_err(|_| JsError::new("entropy must be >= 32 bytes"))?,
        );

        let (masked_card, proof) =
            BnCardProtocol::mask(&mut rng, &pp, &shared_key, &original_card, &BnScalar::one())
                .map_err(|_| JsError::new("failed to mask card"))?;
        BnMaskingOutputBuf::to_js(masked_card, proof)
    }

    pub fn shuffle_and_remask(
        pp: JsValue,
        shared_key: JsValue,
        deck: Vec<JsValue>,
        entropy: &[u8],
    ) -> Result<JsValue, JsError> {
        let pp = BnParamsBuf::from_js(pp)?;
        if pp.num_cards() != deck.len() {
            return Err(JsError::new(
                format!(
                    "deck length must match protocol params. params currently set to {} cards",
                    pp.num_cards()
                )
                .as_str(),
            ));
        }

        let shared_key = BnPublicKeyBuf::from_js(shared_key)?;
        let mut rng = StdRng::from_seed(
            entropy[0..32]
                .try_into()
                .map_err(|_| JsError::new("entropy must be >= 32 bytes"))?,
        );

        let masking_factors = sample_vector(&mut rng, deck.len());
        let permutation = Permutation::new(&mut rng, deck.len());

        let deck = deck
            .into_iter()
            .map(|card| BnMaskedCardBuf::from_js(card))
            .collect::<Result<Vec<_>, _>>()?;
        let (shuffled_deck, proof) = BnCardProtocol::shuffle_and_remask(
            &mut rng,
            &pp,
            &shared_key,
            &deck,
            &masking_factors,
            &permutation,
        )
        .map_err(|_| JsError::new("failed to shuffle and remask deck"))?;

        BnShuffleOutputBuf::to_js(shuffled_deck, proof)
    }

    pub fn compute_reveal_token(
        pp: JsValue,
        sk: JsValue,
        pk: JsValue,
        masked_card: JsValue,
        entropy: &[u8],
    ) -> Result<JsValue, JsError> {
        let pp = BnParamsBuf::from_js(pp)?;
        let sk = BnPlayerSecretKeyBuf::from_js(sk)?;
        let pk = BnPublicKeyBuf::from_js(pk)?;
        let masked_card = BnMaskedCardBuf::from_js(masked_card)?;
        let mut rng = StdRng::from_seed(
            entropy[0..32]
                .try_into()
                .map_err(|_| JsError::new("entropy must be >= 32 bytes"))?,
        );

        let (reveal_token, proof) =
            BnCardProtocol::compute_reveal_token(&mut rng, &pp, &sk, &pk, &masked_card)
                .map_err(|_| JsError::new("failed to compute reveal token"))?;
        BnRevealTokenWithProofBuf::to_js(reveal_token, proof)
    }

    pub fn unmask(
        pp: JsValue,
        tokens_with_proofs: Vec<JsValue>,
        associated_pks: Vec<JsValue>,
        masked_card: JsValue,
    ) -> Result<JsValue, JsError> {
        let pp = BnParamsBuf::from_js(pp)?;
        let masked_card = BnMaskedCardBuf::from_js(masked_card)?;

        let mut decryption_key = Vec::new();
        for (token_with_proof, pk) in tokens_with_proofs.into_iter().zip(associated_pks.iter()) {
            let (token, proof) = BnRevealTokenWithProofBuf::from_js(token_with_proof)?;
            let pk = BnPublicKeyBuf::from_js(pk.clone())?;
            decryption_key.push((token, proof, pk));
        }

        let card = BnCardProtocol::unmask(&pp, &decryption_key, &masked_card, false)
            .map_err(|_| JsError::new("failed to unmask card"))?;
        BnCardBuf::to_js(card)
    }
}

pub fn get_card_elems_buf(num_cards: usize) -> Result<Vec<BnCardBuf>, SerializationError> {
    let mut card_elems = Vec::new();
    let mut g = EdwardsProjective::prime_subgroup_generator();
    for _ in 0..num_cards {
        let card_elem = el_gamal::Plaintext(g.into_affine());
        card_elems.push(BnCardBuf::serialize(card_elem)?);

        g = g.double();
    }

    Ok(card_elems)
}

#[cfg(feature = "js")]
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn get_card_elemns_js(num_cards: usize) -> Result<Vec<JsValue>, JsError> {
    let mut card_elems = Vec::new();
    let mut g = EdwardsProjective::prime_subgroup_generator();
    for _ in 0..num_cards {
        let card_elem = el_gamal::Plaintext(g.into_affine());
        card_elems.push(BnCardBuf::to_js(card_elem)?);

        g = g.double();
    }

    Ok(card_elems)
}
