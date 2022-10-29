use std::time::{SystemTime, UNIX_EPOCH};

use rand::{thread_rng, Rng};
use sea_orm::{entity::prelude::*, ActiveValue::NotSet, IntoActiveModel, Set};
use serde::{ser::SerializeStruct, Serialize};

#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    /// Telegram User ID
    pub id: i64,

    #[sea_orm(default_value = 1000)]
    /// User balance
    pub balance: i32,
    #[sea_orm(default_value = 0)]
    /// User XP
    pub xp: i32,
    #[sea_orm(default_value = 0)]
    /// Unix time of starting breaking casino
    pub casino_breaking_start: i64,
    #[sea_orm(nullable)]
    /// Type of casino to break
    pub casino_type: Option<CasinoType>,
}

#[derive(Debug, Serialize, PartialEq, Eq, Copy, Clone, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
#[serde(rename_all = "camelCase")]
pub enum CasinoType {
    #[sea_orm(num_value = 0)]
    Poor,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn casino_breaking_time_left(&self) -> i64 {
        0
    }

    pub async fn calculate_casino_progress(self, db: &DatabaseConnection) -> Result<Self, DbErr> {
        let casino_type = match self.casino_type {
            Some(x) => x,
            None => return Ok(self),
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if now < self.casino_breaking_start + casino_type.time_to_break() {
            return Ok(self);
        }

        let (balance, xp) = (self.balance, self.xp);

        let mut active = self.into_active_model();
        {
            let mut rng = thread_rng();

            active.balance = Set(balance + rng.gen_range(casino_type.money_range()));
            active.xp = Set(xp + rng.gen_range(casino_type.xp_range()));
            active.casino_type = NotSet;
        }

        active.update(db).await
    }
}

impl Serialize for Model {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut s = serializer.serialize_struct("Model", 5)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("xp", &self.xp)?;
        s.serialize_field("balance", &self.balance)?;
        s.serialize_field(
            "casino_breaking_left",
            &(now - self.casino_type.map(|f| f.time_to_break()).unwrap_or(0)),
        )?;
        s.serialize_field("casino_type", &self.casino_type)?;

        s.end()
    }
}

pub mod casinotype {
    use super::CasinoType;
    use std::ops::Range;

    macro_rules! impl_casinotype {
        ($($type:ident -> (money: $money_range:expr, time: $time_range:expr, xp: $xp_range:expr)),+) => {
            pub const fn money_range(&self) -> Range<i32> {
                match self {
                    $(
                        Self::$type => $money_range,
                    )+
                }
            }

            pub const fn xp_range(&self) -> Range<i32> {
                match self {
                    $(
                        Self::$type => $xp_range,
                    )+
                }
            }

            pub const fn time_to_break(&self) -> i64 {
                match self {
                    $(
                        Self::$type => $time_range,
                    )+
                }
            }
        };
    }

    impl CasinoType {
        impl_casinotype! {
            // TODO: change it
            Poor -> (money: 500..1200, time: 15, xp: 7..18)
        }
    }
}
