use sea_orm::entity::prelude::*;

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

#[derive(Debug, PartialEq, Clone, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum CasinoType {
    #[sea_orm(num_value = 0)]
    Poor,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
