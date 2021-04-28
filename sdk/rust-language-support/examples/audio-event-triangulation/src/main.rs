//! An implementation of triangulation of audio event data
//!
//! TODO consistent documentation with other examples
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSING.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use libveracruz::{host, return_code};
use std::convert::TryInto;

struct AudioEvent {
    timestamp: u32,
    location: (i32, i32),
    samples: Vec<i16>,
}

impl AudioEvent {
    fn power(&self) -> f64 {
        // compute as avg per single sample, assumes common bitrate
        let mut p: f64 = 0.0;
        for x in self.samples.iter() {
            p += x.abs() as f64;
        }

        p / (self.samples.len() as f64)
    }
}

fn decode_audio_event(event: &[u8]) -> AudioEvent {
    AudioEvent{
        timestamp: u32::from_le_bytes(event[0..4].try_into().unwrap()),
        location: (
            i32::from_le_bytes(event[4.. 8].try_into().unwrap()),
            i32::from_le_bytes(event[8..12].try_into().unwrap())
        ),
        samples: (12..event.len()).step_by(2)
            .map(|i| i16::from_le_bytes(event[i..i+2].try_into().unwrap()))
            .collect::<Vec<_>>()
    }
}

fn triangulate(events: &[AudioEvent]) -> (i32, i32) {
    // solving
    // (x−x1)^2 + (y−y1)^2 = d1^2
    // (x−x2)^2 + (y−y2)^2 = d2^2 
    // (x−x3)^2 + (y−y3)^2 = d3^2 
    //
    // let
    // a = (-2x1 + 2x2)
    // b = (-2y1 + 2y2)
    // c = d1^2-d2^2 - x1^2+x2^2 - y1^2+y2^2
    // d = (-2x2 + 2x3)
    // e = (-2y2 + 2y3)
    // f = d2^2-d3^2 - x2^2+x3^2 - y2^2+y3^2
    //
    // gives us
    // x = (ce - fb) / (ea - bd)
    // y = (cd - af) / (bd - ae)
    //
    let (y1, x1) = events[0].location;
    let (y2, x2) = events[1].location;
    let (y3, x3) = events[2].location;
    let (y1, x1) = (y1 as f64, x1 as f64);
    let (y2, x2) = (y2 as f64, x2 as f64);
    let (y3, x3) = (y3 as f64, x3 as f64);
    let d1 = events[0].power();
    let d2 = events[1].power();
    let d3 = events[2].power();

    let a = -2.0*x1 + 2.0*x2;
    let b = -2.0*y1 + 2.0*y2;
    let c = d1.powf(2.0)-d2.powf(2.0) - x1.powf(2.0)+x2.powf(2.0) - y1.powf(2.0)+y2.powf(2.0);
    let d = -2.0*x2 + 2.0*x3;
    let e = -2.0*y2 + 2.0*y3;
    let f = d2.powf(2.0)-d3.powf(2.0) - x2.powf(2.0)+x3.powf(2.0) - y2.powf(2.0)+y3.powf(2.0);

    let x = (c*e - f*b) / (e*a - b*d);
    let y = (c*d - a*f) / (b*d - a*e);

    (y as i32, x as i32)
}

fn encode_location(location: (i32, i32)) -> Vec<u8> {
    location.0.to_le_bytes().iter()
        .chain(location.1.to_le_bytes().iter())
        .map(|x| *x)
        .collect::<Vec<_>>()
}

/// entry point
fn main() -> return_code::Veracruz {
    // read inputs through libveracruz
    let raw_events: Vec<Vec<u8>> = host::read_all_inputs();

    // decode
    let events = raw_events.iter()
        .map(|raw_event| decode_audio_event(&raw_event[..]))
        .collect::<Vec<_>>();

    // triangulate
    let location = triangulate(&events);

    // encode
    let raw_location = encode_location(location);

    // write our output through libveracruz
    host::write_output(&raw_location).unwrap();
    return_code::success()
}
