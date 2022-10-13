use core::fmt::Debug;

use embassy_executor::{
    executor::Spawner,
    time::{Duration, Timer},
};
use embassy_util::{blocking_mutex::raw::CriticalSectionRawMutex, channel::mpmc};
use hal::{
    gpio::{
        p0::{P0_06, P0_08},
        Output, PushPull,
    },
    prelude::OutputPin,
};

pub(crate) type GreenPin = P0_06<Output<PushPull>>;
pub(crate) type RedPin = P0_08<Output<PushPull>>;

#[derive(Debug, PartialEq, Eq)]
pub enum LedState {
    /// Disable all LEDs
    Off,
    /// Token has started in an unprovisioned state. This is the case on the
    /// first start, or after reset.
    TokenNotProvisioned,
    /// Token provisioning has just been completed.
    TokenProvisioningComplete,
    /// Token is already provisioned and waiting for the platform to attempt
    /// either provisioning or attestation.
    TokenWaiting,
    /// Platform provisioning was successful.
    PlatformProvisioningOk,
    /// Platform attestation is successful and there is at least one client with
    /// access to FTS.
    AttestationOk,
    /// Platform attestation failed.
    AttestationFailed,
}

const CMD_QUEUE_SIZE: usize = 10;
const SHORT_BLINK_PERIOD: Duration = Duration::from_millis(100);

pub type CommandSender = mpmc::Sender<'static, CriticalSectionRawMutex, LedState, CMD_QUEUE_SIZE>;

static CHANNEL: mpmc::Channel<CriticalSectionRawMutex, LedState, CMD_QUEUE_SIZE> =
    mpmc::Channel::new();

struct Led<P> {
    pin: P,
    cached_state: bool,
}

impl<P> Led<P>
where
    P: OutputPin,
    P::Error: Debug,
{
    pub fn new(pin: P) -> Self {
        let mut this = Self {
            pin,
            cached_state: true,
        };
        this.control(false);
        this
    }

    pub fn control(&mut self, enable: bool) {
        if enable == self.cached_state {
            return;
        }

        self.cached_state = enable;

        if enable {
            self.pin.set_low().unwrap();
        } else {
            self.pin.set_high().unwrap();
        }
    }
}

async fn led_controller(
    rx: mpmc::Receiver<'static, CriticalSectionRawMutex, LedState, CMD_QUEUE_SIZE>,
    green: GreenPin,
    red: RedPin,
) {
    let mut green = Led::new(green);
    let mut red = Led::new(red);

    let mut state = LedState::Off;
    let mut state_changed = true;
    let mut attestation_ok = false;
    let mut attestation_failed = false;

    'main_loop: loop {
        macro_rules! poll {
            () => {{
                state = rx.recv().await;
                state_changed = true;
                continue 'main_loop;
            }};
            ($fut:expr) => {{
                use embassy_util::Either;
                match embassy_util::select(rx.recv(), $fut).await {
                    Either::First(s) => {
                        state = s;
                        state_changed = true;
                        continue 'main_loop;
                    }
                    Either::Second(r) => r,
                }
            }};
        }

        if state_changed {
            state_changed = false;
            trace!("LED controller state: {:?}", state);
            if state == LedState::AttestationOk {
                attestation_ok = true;
            } else if state == LedState::AttestationFailed {
                attestation_failed = true;
            } else {
                attestation_ok = false;
                attestation_failed = false;
            }
        }

        match state {
            LedState::Off => {
                green.control(false);
                red.control(false);
                poll!()
            }
            LedState::TokenNotProvisioned => {
                green.control(false);
                red.control(true);
                poll!()
            }
            LedState::TokenProvisioningComplete => {
                red.control(false);
                green.control(true);

                // Special case: don't poll control channel to avoid
                // interrupting in a middle of sequence
                Timer::after(SHORT_BLINK_PERIOD).await;
                green.control(false);
                Timer::after(SHORT_BLINK_PERIOD).await;

                poll!()
            }
            LedState::TokenWaiting => {
                green.control(true);
                red.control(true);
                poll!(Timer::after(SHORT_BLINK_PERIOD));
                green.control(false);
                red.control(false);
                poll!(Timer::after(Duration::from_secs(5)));
            }
            LedState::PlatformProvisioningOk => {
                red.control(false);
                green.control(true);
                for _ in 0..3 {
                    Timer::after(SHORT_BLINK_PERIOD).await;
                    green.control(false);
                    Timer::after(SHORT_BLINK_PERIOD).await;
                    green.control(true);
                }

                Timer::after(SHORT_BLINK_PERIOD).await;
                green.control(false);
                poll!()
            }
            LedState::AttestationOk | LedState::AttestationFailed => {
                green.control(attestation_ok);
                red.control(attestation_failed);
                if attestation_failed {
                    Timer::after(Duration::from_secs(5)).await;
                    red.control(false);
                }
                poll!()
            }
        }
    }
}

#[embassy_executor::task]
async fn led_controller_task(
    rx: mpmc::Receiver<'static, CriticalSectionRawMutex, LedState, CMD_QUEUE_SIZE>,
    green: GreenPin,
    red: RedPin,
) {
    // rust-analyzer doesn't handle embassy_executor::task macro properly, use
    // separate to workaround this
    led_controller(rx, green, red).await
}

pub(crate) fn init(spawner: &Spawner, green: GreenPin, red: RedPin) {
    spawner.must_spawn(led_controller_task(CHANNEL.receiver(), green, red));
}

pub fn control(state: LedState) {
    CHANNEL.try_send(state).unwrap();
}
