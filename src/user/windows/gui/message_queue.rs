//! Posted thread messages and the low-priority synthesized WM_QUIT.

use std::collections::VecDeque;

pub(crate) const WM_QUIT: u32 = 0x0012;
const POST_LIMIT: usize = 10_000;

#[derive(Clone, Copy)]
pub(crate) struct Message {
    pub(crate) id: u32,
    pub(crate) wparam: u64,
    pub(crate) lparam: u64,
    pub(crate) time: u32,
    pub(crate) point: [i32; 2],
}

impl Message {
    pub(crate) fn encode(self) -> [u8; 48] {
        let mut output = [0; 48];
        output[8..12].copy_from_slice(&self.id.to_le_bytes());
        output[16..24].copy_from_slice(&self.wparam.to_le_bytes());
        output[24..32].copy_from_slice(&self.lparam.to_le_bytes());
        output[32..36].copy_from_slice(&self.time.to_le_bytes());
        output[36..40].copy_from_slice(&self.point[0].to_le_bytes());
        output[40..44].copy_from_slice(&self.point[1].to_le_bytes());
        output
    }
}

#[derive(Clone, Copy)]
enum Ready {
    Posted(usize),
    Quit(u32),
}

#[derive(Default)]
pub(crate) struct Queue {
    posted: VecDeque<Message>,
    quit: Option<u32>,
}

impl Queue {
    pub(crate) fn post(&mut self, message: Message) -> bool {
        if self.posted.len() >= POST_LIMIT {
            return false;
        }
        self.posted.push_back(message);
        true
    }

    pub(crate) fn quit(&mut self, code: u32) {
        self.quit = Some(code);
    }

    fn ready(&self, minimum: u32, maximum: u32) -> Option<Ready> {
        if self.posted.is_empty() {
            return self.quit.map(Ready::Quit);
        }
        self.posted
            .iter()
            .position(|message| {
                (minimum == 0 && maximum == 0) || (minimum..=maximum).contains(&message.id)
            })
            .map(Ready::Posted)
    }

    pub(crate) fn has_message(&self, minimum: u32, maximum: u32) -> bool {
        self.ready(minimum, maximum).is_some()
    }

    pub(crate) fn get(
        &mut self,
        minimum: u32,
        maximum: u32,
        remove: bool,
        now: u32,
        point: [i32; 2],
    ) -> Option<Message> {
        match self.ready(minimum, maximum)? {
            Ready::Posted(index) if remove => self.posted.remove(index),
            Ready::Posted(index) => Some(self.posted[index]),
            Ready::Quit(code) => {
                if remove {
                    self.quit = None;
                }
                Some(Message {
                    id: WM_QUIT,
                    wparam: u64::from(code),
                    lparam: 0,
                    time: now,
                    point,
                })
            }
        }
    }
}
