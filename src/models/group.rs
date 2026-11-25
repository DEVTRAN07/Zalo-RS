//! Group types: settings, topics, info, and membership.

use serde::{Deserialize, Serialize};

/// Group settings.
///
/// All fields default to `0` when absent: Zalo may add, drop or rename
/// settings between responses, and a missing setting must not fail parsing
/// the whole group info (callers usually only need name/members/admins).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupSetting {
    #[serde(rename = "blockName", default)]
    pub block_name: i64,
    #[serde(rename = "signAdminMsg", default)]
    pub sign_admin_msg: i64,
    #[serde(rename = "addMemberOnly", default)]
    pub add_member_only: i64,
    #[serde(rename = "setTopicOnly", default)]
    pub set_topic_only: i64,
    #[serde(rename = "enableMsgHistory", default)]
    pub enable_msg_history: i64,
    #[serde(rename = "joinAppr", default)]
    pub join_appr: i64,
    #[serde(rename = "lockCreatePost", default)]
    pub lock_create_post: i64,
    #[serde(rename = "lockCreatePoll", default)]
    pub lock_create_poll: i64,
    #[serde(rename = "lockSendMsg", default)]
    pub lock_send_msg: i64,
    #[serde(rename = "lockViewMember", default)]
    pub lock_view_member: i64,
    #[serde(rename = "bannFeature", default)]
    pub bann_feature: i64,
    #[serde(rename = "dirtyMedia", default)]
    pub dirty_media: i64,
    #[serde(rename = "banDuration", default)]
    pub ban_duration: i64,
}

/// Type of a group topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupTopicType {
    Note = 0,
    Message = 2,
    Poll = 3,
}

/// Parameters for a note topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopicNoteParams {
    #[serde(rename = "client_msg_id")]
    pub client_msg_id: String,
    #[serde(rename = "global_msg_id")]
    pub global_msg_id: String,
    pub title: String,
}

/// Parameters for a text message topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopicTextMessageParams {
    #[serde(rename = "senderUid")]
    pub sender_uid: String,
    #[serde(rename = "senderName")]
    pub sender_name: String,
    #[serde(rename = "client_msg_id")]
    pub client_msg_id: String,
    #[serde(rename = "global_msg_id")]
    pub global_msg_id: String,
    #[serde(rename = "msg_type")]
    pub msg_type: i64,
    pub title: String,
}

/// Parameters for a voice message topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopicVoiceMessageParams {
    #[serde(rename = "senderUid")]
    pub sender_uid: String,
    #[serde(rename = "senderName")]
    pub sender_name: String,
    #[serde(rename = "client_msg_id")]
    pub client_msg_id: String,
    #[serde(rename = "global_msg_id")]
    pub global_msg_id: String,
    #[serde(rename = "msg_type")]
    pub msg_type: i64,
    pub title: String,
    pub thumb: String,
}

/// Parameters for an image message topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopicImageMessageParams {
    #[serde(rename = "senderUid")]
    pub sender_uid: String,
    #[serde(rename = "senderName")]
    pub sender_name: String,
    #[serde(rename = "client_msg_id")]
    pub client_msg_id: String,
    #[serde(rename = "global_msg_id")]
    pub global_msg_id: String,
    #[serde(rename = "msg_type")]
    pub msg_type: i64,
    pub title: String,
    pub thumb: String,
}

/// Parameters for a video message topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopicVideoMessageParams {
    #[serde(rename = "senderUid")]
    pub sender_uid: String,
    #[serde(rename = "senderName")]
    pub sender_name: String,
    #[serde(rename = "client_msg_id")]
    pub client_msg_id: String,
    #[serde(rename = "global_msg_id")]
    pub global_msg_id: String,
    #[serde(rename = "msg_type")]
    pub msg_type: i64,
    pub title: String,
    pub thumb: String,
}

/// Parameters for a file message topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopicFileMessageParams {
    #[serde(rename = "senderUid")]
    pub sender_uid: String,
    #[serde(rename = "senderName")]
    pub sender_name: String,
    #[serde(rename = "client_msg_id")]
    pub client_msg_id: String,
    #[serde(rename = "global_msg_id")]
    pub global_msg_id: String,
    #[serde(rename = "msg_type")]
    pub msg_type: i64,
    pub title: String,
    pub extra: GroupTopicFileExtra,
}

/// Extra data for a file message topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopicFileExtra {
    #[serde(rename = "fileSize")]
    pub file_size: String,
    pub checksum: String,
    #[serde(rename = "checksumSha")]
    pub checksum_sha: serde_json::Value,
    #[serde(rename = "fileExt")]
    pub file_ext: String,
    pub fdata: String,
    #[serde(rename = "fType")]
    pub f_type: i64,
}

/// Parameters for a gif message topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopicGifMessageParams {
    #[serde(rename = "senderUid")]
    pub sender_uid: String,
    #[serde(rename = "senderName")]
    pub sender_name: String,
    #[serde(rename = "client_msg_id")]
    pub client_msg_id: String,
    #[serde(rename = "global_msg_id")]
    pub global_msg_id: String,
    #[serde(rename = "msg_type")]
    pub msg_type: i64,
    pub title: String,
    pub thumb: String,
}

/// Union of group topic message parameters.
#[derive(Debug, Clone)]
pub enum GroupTopicMessageParams {
    Text(GroupTopicTextMessageParams),
    Voice(GroupTopicVoiceMessageParams),
    Image(GroupTopicImageMessageParams),
    Video(GroupTopicVideoMessageParams),
    File(GroupTopicFileMessageParams),
    Gif(GroupTopicGifMessageParams),
}

/// Parameters for a poll topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopicPollParams {
    #[serde(rename = "pollId")]
    pub poll_id: i64,
    pub title: String,
}

/// Other / unknown topic parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopicOtherParams {
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A group topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTopic {
    #[serde(rename = "type")]
    pub type_: GroupTopicType,
    pub color: i64,
    pub emoji: String,
    #[serde(rename = "startTime")]
    pub start_time: i64,
    pub duration: i64,
    pub params: serde_json::Value,
    pub id: String,
    #[serde(rename = "creatorId")]
    pub creator_id: String,
    #[serde(rename = "createTime")]
    pub create_time: i64,
    #[serde(rename = "editorId")]
    pub editor_id: String,
    #[serde(rename = "editTime")]
    pub edit_time: i64,
    pub repeat: i64,
    pub action: i64,
}

/// Type of a group.
///
/// `Unknown` catches any type value Zalo may introduce later (e.g. a new
/// community subtype) so `get_group_info` keeps working instead of failing
/// the whole response on one unfamiliar `type`.
///
/// NOTE: `Deserialize` is implemented by hand (not derived) because the
/// derived impl with `#[serde(other)]` rejects the integer wire values
/// Zalo actually sends (`"type": 1` / `2` fail with "expected value").
/// The manual impl accepts both integers and variant names, mapping any
/// other value to `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub enum GroupType {
    Group = 1,
    Community = 2,
    #[default]
    Unknown,
}

impl<'de> Deserialize<'de> for GroupType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct GroupTypeVisitor;

        impl<'de> serde::de::Visitor<'de> for GroupTypeVisitor {
            type Value = GroupType;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a group type (1, 2, or a variant name)")
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<GroupType, E> {
                Ok(match v {
                    1 => GroupType::Group,
                    2 => GroupType::Community,
                    _ => GroupType::Unknown,
                })
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<GroupType, E> {
                Ok(match v {
                    1 => GroupType::Group,
                    2 => GroupType::Community,
                    _ => GroupType::Unknown,
                })
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<GroupType, E> {
                Ok(match v {
                    "Group" => GroupType::Group,
                    "Community" => GroupType::Community,
                    _ => GroupType::Unknown,
                })
            }
        }

        deserializer.deserialize_any(GroupTypeVisitor)
    }
}

/// Current member of a group.
///
/// All fields default when absent so one member with a missing/extra field
/// does not fail parsing the whole group info.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupCurrentMem {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "dName", default)]
    pub d_name: String,
    #[serde(rename = "zaloName", default)]
    pub zalo_name: String,
    #[serde(default)]
    pub avatar: String,
    #[serde(rename = "avatar_25", default)]
    pub avatar_25: String,
    #[serde(rename = "accountStatus", default)]
    pub account_status: i64,
    #[serde(default)]
    pub type_: i64,
}

/// Deserialize a string field that Zalo may also send as a number
/// (e.g. `version` sent as `3` instead of `"3"`).
fn de_string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringOrNumber;

    impl<'de> serde::de::Visitor<'de> for StringOrNumber {
        type Value = String;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or a number")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<String, E> {
            Ok(v.to_string())
        }

        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<String, E> {
            Ok(v)
        }

        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<String, E> {
            Ok(v.to_string())
        }

        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<String, E> {
            Ok(v.to_string())
        }
    }

    deserializer.deserialize_any(StringOrNumber)
}

/// Group info.
///
/// Every field defaults when absent: callers (e.g. `/bot status`, the
/// router) usually only need name/members/admins, so a field Zalo drops,
/// adds or renames must not fail the whole `get_group_info` response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupInfo {
    #[serde(rename = "groupId", default)]
    pub group_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub desc: String,
    #[serde(rename = "type", default)]
    pub type_: GroupType,
    #[serde(rename = "creatorId", default)]
    pub creator_id: String,
    #[serde(default, deserialize_with = "de_string_or_number")]
    pub version: String,
    #[serde(default)]
    pub avt: String,
    #[serde(rename = "fullAvt", default)]
    pub full_avt: String,
    #[serde(rename = "memberIds", default)]
    pub member_ids: Vec<String>,
    #[serde(rename = "adminIds", default)]
    pub admin_ids: Vec<String>,
    #[serde(rename = "currentMems", default)]
    pub current_mems: Vec<GroupCurrentMem>,
    #[serde(default)]
    pub update_mems: Vec<serde_json::Value>,
    #[serde(default)]
    pub admins: Vec<serde_json::Value>,
    #[serde(rename = "hasMoreMember", default)]
    pub has_more_member: i64,
    #[serde(rename = "subType", default)]
    pub sub_type: i64,
    #[serde(rename = "totalMember", default)]
    pub total_member: i64,
    #[serde(rename = "maxMember", default)]
    pub max_member: i64,
    #[serde(default)]
    pub setting: GroupSetting,
    #[serde(rename = "createdTime", default)]
    pub created_time: i64,
    #[serde(default)]
    pub visibility: i64,
    #[serde(rename = "globalId", default)]
    pub global_id: String,
    /// 1: True, 0: False
    #[serde(default)]
    pub e2ee: i64,
    #[serde(rename = "extraInfo", default)]
    pub extra_info: GroupExtraInfo,
}

/// Extra info inside GroupInfo.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupExtraInfo {
    #[serde(rename = "enable_media_store", default)]
    pub enable_media_store: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_info_minimal_json_parses_with_defaults() {
        let info: GroupInfo =
            serde_json::from_str(r#"{"groupId":"123","name":"Test"}"#).unwrap();
        assert_eq!(info.group_id, "123");
        assert_eq!(info.name, "Test");
        assert_eq!(info.type_, GroupType::Unknown);
        assert!(info.member_ids.is_empty());
        assert_eq!(info.setting.block_name, 0);
        assert_eq!(info.extra_info.enable_media_store, 0);
    }

    #[test]
    fn group_info_unknown_type_maps_to_unknown() {
        // A future community subtype (or any new type value) must not fail
        // the whole get_group_info response.
        let info: GroupInfo = serde_json::from_str(
            r#"{"groupId":"1","name":"x","type":99,"subType":7}"#,
        )
        .unwrap();
        assert_eq!(info.type_, GroupType::Unknown);
        assert_eq!(info.sub_type, 7);
    }

    #[test]
    fn group_info_known_types_still_parse() {
        let group: GroupInfo =
            serde_json::from_str(r#"{"groupId":"1","name":"x","type":1}"#).unwrap();
        assert_eq!(group.type_, GroupType::Group);
        let community: GroupInfo =
            serde_json::from_str(r#"{"groupId":"1","name":"x","type":2}"#).unwrap();
        assert_eq!(community.type_, GroupType::Community);
    }

    #[test]
    fn group_info_numeric_version_parses_as_string() {
        let info: GroupInfo = serde_json::from_str(
            r#"{"groupId":"1","name":"x","version":3}"#,
        )
        .unwrap();
        assert_eq!(info.version, "3");
        let info: GroupInfo = serde_json::from_str(
            r#"{"groupId":"1","name":"x","version":"3"}"#,
        )
        .unwrap();
        assert_eq!(info.version, "3");
    }

    #[test]
    fn group_setting_empty_object_parses() {
        let setting: GroupSetting = serde_json::from_str("{}").unwrap();
        assert_eq!(setting.block_name, 0);
        assert_eq!(setting.ban_duration, 0);
    }

    #[test]
    fn group_info_partial_member_parses() {
        let info: GroupInfo = serde_json::from_str(
            r#"{"groupId":"1","name":"x","currentMems":[{"id":"42"}]}"#,
        )
        .unwrap();
        assert_eq!(info.current_mems.len(), 1);
        assert_eq!(info.current_mems[0].id, "42");
        assert_eq!(info.current_mems[0].d_name, "");
    }
}
