//! Checks on the ATECC608B's slot-0 configuration, before the firmware does
//! anything one-way with it.
//!
//! Locking the configuration zone is permanent, so the firmware only locks a
//! chip whose slot 0 is exactly as Microchip ships a blank ATECC608B
//! ([`FACTORY_SLOT_CONFIG`], [`FACTORY_KEY_CONFIG`]). On a chip whose
//! configuration is already locked, it accepts slot 0 only if it can still
//! serve as the device key: a P-256 private key that signs external messages,
//! whose public key can be read, with no authorization or random-nonce
//! requirement the firmware does not meet, and (while the slot is unlocked)
//! that GenKey may write and the slot can be locked.
//!
//! Bit meanings from the ATECC608B datasheet (SlotConfig / KeyConfig).

/// SlotConfig of slot 0 on a blank ATECC608B: ReadKey 0x3 (external and
/// internal signatures), IsSecret, WriteConfig 0x2 (GenKey may write).
pub const FACTORY_SLOT_CONFIG: u16 = 0x2083;
/// KeyConfig of slot 0 on a blank ATECC608B: Private, PubInfo, KeyType P-256,
/// Lockable.
pub const FACTORY_KEY_CONFIG: u16 = 0x0033;

const KC_PRIVATE: u16 = 1 << 0;
const KC_PUB_INFO: u16 = 1 << 1;
const KC_KEY_TYPE_SHIFT: u16 = 2;
const KC_KEY_TYPE_P256: u16 = 4;
const KC_LOCKABLE: u16 = 1 << 5;
const KC_REQ_RANDOM: u16 = 1 << 6;
const KC_REQ_AUTH: u16 = 1 << 7;
const KC_PERSISTENT_DISABLE: u16 = 1 << 12;

/// ReadKey bit 0 on a private key: external messages may be signed.
const SC_EXTERNAL_SIGN: u16 = 1 << 0;
/// IsSecret: the key can never be read out.
const SC_IS_SECRET: u16 = 1 << 7;
/// WriteConfig bit 1 (bit 13) on a private key: GenKey may write the slot.
const SC_GENKEY: u16 = 1 << 13;

/// What the chip's lock bytes say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockState {
    pub config_locked: bool,
    pub slot0_locked: bool,
}

/// Whether slot 0 (`slot_config`, `key_config`) may be used, given the lock
/// state. `Err` explains why not; the firmware then refuses to touch the chip.
pub fn check_slot0(slot_config: u16, key_config: u16, lock: LockState) -> Result<(), String> {
    if !lock.config_locked {
        // About to be locked for good: only the known factory layout.
        if slot_config != FACTORY_SLOT_CONFIG || key_config != FACTORY_KEY_CONFIG {
            return Err(format!(
                "slot 0 is not the ATECC608B factory configuration \
                 (SlotConfig 0x{slot_config:04X}, KeyConfig 0x{key_config:04X}; \
                 expected 0x{FACTORY_SLOT_CONFIG:04X}/0x{FACTORY_KEY_CONFIG:04X}); \
                 not locking it"
            ));
        }
        return Ok(());
    }

    let mut problems = Vec::new();
    if key_config & KC_PRIVATE == 0 {
        problems.push("not a private key");
    }
    if (key_config >> KC_KEY_TYPE_SHIFT) & 0x7 != KC_KEY_TYPE_P256 {
        problems.push("not a P-256 key");
    }
    if key_config & KC_PUB_INFO == 0 {
        problems.push("its public key cannot be read (PubInfo clear)");
    }
    if key_config & KC_REQ_RANDOM != 0 {
        problems.push("signing requires a random nonce (ReqRandom)");
    }
    if key_config & KC_REQ_AUTH != 0 {
        problems.push("use requires authorization (ReqAuth)");
    }
    if key_config & KC_PERSISTENT_DISABLE != 0 {
        problems.push("use requires the persistent latch (PersistentDisable)");
    }
    if slot_config & SC_EXTERNAL_SIGN == 0 {
        problems.push("external messages cannot be signed");
    }
    if slot_config & SC_IS_SECRET == 0 {
        problems.push("the key is not secret (IsSecret clear)");
    }
    if !lock.slot0_locked {
        // The key still has to be generated and the slot locked.
        if slot_config & SC_GENKEY == 0 {
            problems.push("GenKey may not write the slot");
        }
        if key_config & KC_LOCKABLE == 0 {
            problems.push("the slot cannot be locked");
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "slot 0 cannot hold the device key (SlotConfig 0x{slot_config:04X}, \
             KeyConfig 0x{key_config:04X}): {}",
            problems.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLANK: LockState = LockState {
        config_locked: false,
        slot0_locked: false,
    };
    const CONFIGURED: LockState = LockState {
        config_locked: true,
        slot0_locked: false,
    };
    const DONE: LockState = LockState {
        config_locked: true,
        slot0_locked: true,
    };

    #[test]
    fn the_factory_configuration_is_accepted_in_every_state() {
        for lock in [BLANK, CONFIGURED, DONE] {
            assert_eq!(
                check_slot0(FACTORY_SLOT_CONFIG, FACTORY_KEY_CONFIG, lock),
                Ok(()),
                "{lock:?}"
            );
        }
    }

    #[test]
    fn an_unlocked_chip_is_only_locked_with_the_factory_layout() {
        // Usable, but not what the firmware verified: not locked.
        assert!(check_slot0(FACTORY_SLOT_CONFIG | 0x0400, FACTORY_KEY_CONFIG, BLANK).is_err());
        assert!(check_slot0(FACTORY_SLOT_CONFIG, FACTORY_KEY_CONFIG | KC_REQ_AUTH, BLANK).is_err());
    }

    #[test]
    fn a_locked_slot_that_cannot_sign_for_us_is_refused() {
        for (bit, why) in [
            (KC_REQ_AUTH, "ReqAuth"),
            (KC_REQ_RANDOM, "ReqRandom"),
            (KC_PERSISTENT_DISABLE, "PersistentDisable"),
        ] {
            let err = check_slot0(FACTORY_SLOT_CONFIG, FACTORY_KEY_CONFIG | bit, DONE).unwrap_err();
            assert!(err.contains(why), "{err}");
        }
        assert!(check_slot0(FACTORY_SLOT_CONFIG, FACTORY_KEY_CONFIG & !KC_PUB_INFO, DONE).is_err());
        assert!(check_slot0(
            FACTORY_SLOT_CONFIG & !SC_EXTERNAL_SIGN,
            FACTORY_KEY_CONFIG,
            DONE
        )
        .is_err());
        // AES key type in slot 0.
        assert!(check_slot0(FACTORY_SLOT_CONFIG, 0x0019, DONE).is_err());
    }

    #[test]
    fn genkey_and_lockable_matter_only_until_the_slot_is_locked() {
        let no_genkey = FACTORY_SLOT_CONFIG & !SC_GENKEY;
        let not_lockable = FACTORY_KEY_CONFIG & !KC_LOCKABLE;
        assert!(check_slot0(no_genkey, FACTORY_KEY_CONFIG, CONFIGURED).is_err());
        assert!(check_slot0(FACTORY_SLOT_CONFIG, not_lockable, CONFIGURED).is_err());
        assert_eq!(check_slot0(no_genkey, not_lockable, DONE), Ok(()));
    }
}
