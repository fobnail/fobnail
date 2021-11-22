use hal::{
    pac::{interrupt, TIMER1},
    prelude::*,
};

#[interrupt]
#[allow(non_snake_case)]
fn TIMER1() {}

pub fn init<G, R>(_timer1: TIMER1, _green: G, _red: R)
where
    G: OutputPin,
    R: OutputPin,
{
    /*let port0 = hal::gpio::p0::Parts::new(periph.P0);
    let mut timer: Timer<hal::pac::TIMER0, hal::timer::Periodic> = Timer::periodic(periph.TIMER0);

    // Power on LEDs (active-low)
    let mut green_led = port0.p0_06.into_push_pull_output(Level::Low);
    let mut red_led = port0.p0_08.into_push_pull_output(Level::Low);

    loop {
        // Blink with 1 second intervals
        timer.delay(Timer::<hal::pac::TIMER0, hal::timer::Periodic>::TICKS_PER_SECOND);
        green_led.set_high().unwrap();
        red_led.set_high().unwrap();
        timer.delay(Timer::<hal::pac::TIMER0, hal::timer::Periodic>::TICKS_PER_SECOND);
        green_led.set_low().unwrap();
        red_led.set_low().unwrap();
    }*/
}
