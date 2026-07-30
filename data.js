window.BENCHMARK_DATA = {
  "lastUpdate": 1785427976761,
  "repoUrl": "https://github.com/BorrowSanitizer/bsan",
  "entries": {
    "Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "fbc2fc1818d1be92a27483aa5850e686dc8867f3",
          "message": "Remove `indexmap`.",
          "timestamp": "2026-06-25T10:49:04-04:00",
          "tree_id": "23331ef1e91a24f03cb4322b1fcf757c20b10252",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fbc2fc1818d1be92a27483aa5850e686dc8867f3"
        },
        "date": 1782403856774,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1543.0793929315814,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32430.730225402294, \"min\": 681.5370927265737}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.23988261596451257,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8704847731132409, \"min\": 0.06769690664783796}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.44273554714767,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.980751120959804, \"min\": 6.3101221009895285}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017238213404355285,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0020928322177737975, \"min\": 0.0002751156814834583}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1504.2099542175135,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 29562.69291589114, \"min\": 547.4114307605067}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2859837376422489,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9498733585969336, \"min\": 0.07144842411021436}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 11.003153436662792,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.36397963349311, \"min\": 6.4477904584222525}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0029846382991930136,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0038394961270337797, \"min\": 0.0006777935131860332}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "fbc2fc1818d1be92a27483aa5850e686dc8867f3",
          "message": "Remove `indexmap`.",
          "timestamp": "2026-06-25T14:49:04Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fbc2fc1818d1be92a27483aa5850e686dc8867f3"
        },
        "date": 1782446020532,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1543.1755119743298,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32993.60154328943, \"min\": 640.4652443348723}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2402245146962659,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9073288805474994, \"min\": 0.06558033556108486}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.286690683703089,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.497205690406837, \"min\": 5.46010249811506}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017064301089244074,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0022571884845015867, \"min\": 0.0002441079836429678}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 2038.7212325874777,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 41603.25416571118, \"min\": 998.6590075957778}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.3056084048120172,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.7811470655512245, \"min\": 0.06236720824802958}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 8.766662188946627,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 26.73244623186731, \"min\": 6.703016387667619}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0018984005253323186,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0023611562165052175, \"min\": 0.0002721114587116341}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "fbc2fc1818d1be92a27483aa5850e686dc8867f3",
          "message": "Remove `indexmap`.",
          "timestamp": "2026-06-25T14:49:04Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fbc2fc1818d1be92a27483aa5850e686dc8867f3"
        },
        "date": 1782532101993,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1563.755849312107,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32244.448682481794, \"min\": 713.4258230500459}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2425698959790828,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.898615159344078, \"min\": 0.06573028722581085}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.3721211445723185,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.365141671660325, \"min\": 6.1349726450716755}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0016989510434646722,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002045552541918436, \"min\": 0.0002437933713506126}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1494.9631517939156,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 28807.493554183297, \"min\": 714.9367359594154}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2853559251032534,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9230048181471285, \"min\": 0.07081270625163072}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.93005481291512,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.519108249876496, \"min\": 8.421851637207341}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002948193950052954,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0040094021329215865, \"min\": 0.0006642863684418683}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "fbc2fc1818d1be92a27483aa5850e686dc8867f3",
          "message": "Remove `indexmap`.",
          "timestamp": "2026-06-25T14:49:04Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fbc2fc1818d1be92a27483aa5850e686dc8867f3"
        },
        "date": 1782619172333,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1588.7103091744411,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 33489.84169018238, \"min\": 708.8652022714467}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2418783771265753,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9895642735469539, \"min\": 0.06692460340569642}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.61917721898402,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.24381383133373, \"min\": 6.440702948161859}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017431378300974021,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002126018950185213, \"min\": 0.0002457108628322999}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1538.881895442297,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32538.72419879614, \"min\": 726.5466432805919}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.29209014134791556,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9218972041092142, \"min\": 0.07530585412775008}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.849996749870531,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.19027937640225, \"min\": 8.630635152781407}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0029556110873111756,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0039413568122224915, \"min\": 0.0006803875335634099}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "fbc2fc1818d1be92a27483aa5850e686dc8867f3",
          "message": "Remove `indexmap`.",
          "timestamp": "2026-06-25T14:49:04Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fbc2fc1818d1be92a27483aa5850e686dc8867f3"
        },
        "date": 1782705377649,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1509.81484507175,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 27215.130023918788, \"min\": 711.4211292052894}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2404293974490385,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8937419628270433, \"min\": 0.06671997976616686}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.05920133048418,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.40828678354569, \"min\": 5.634140388099777}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0016340859587774433,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.001990358883487194, \"min\": 0.00024168920090512257}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1511.7045129446751,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32592.308168239637, \"min\": 702.7261383307278}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.26539909994776767,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9154895479008691, \"min\": 0.06955180279841416}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.673099012009354,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.589580942829926, \"min\": 8.044107232130825}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002725444715723371,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003697558328743631, \"min\": 0.0006768255632071954}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "fbc2fc1818d1be92a27483aa5850e686dc8867f3",
          "message": "Remove `indexmap`.",
          "timestamp": "2026-06-25T14:49:04Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fbc2fc1818d1be92a27483aa5850e686dc8867f3"
        },
        "date": 1782791721644,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1647.819980129921,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 40620.05835345409, \"min\": 753.9590755687428}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2404676429095912,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8737313830136947, \"min\": 0.06441388744330966}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.80217620832785,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.25073103537164, \"min\": 6.738664949021367}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017761390914114944,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002144421269492113, \"min\": 0.00024822118781869}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1423.2428386959853,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 30249.620722180112, \"min\": 722.9777026492068}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2881568335209116,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9068945984949682, \"min\": 0.0745460931887799}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.818021519604796,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.41164157791656, \"min\": 8.185734435854078}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.00295453632301958,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0038196684199342853, \"min\": 0.0006535070125178928}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ee02764e9a352d2f5362f9d40dfb3e1396b27aff",
          "message": "Ignored .patch, updated dependencies. (#260)",
          "timestamp": "2026-06-30T11:06:48-04:00",
          "tree_id": "7efc3a4c5e34535c18542cd2708dbff8e9627da6",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/ee02764e9a352d2f5362f9d40dfb3e1396b27aff"
        },
        "date": 1782837042541,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1539.0142531031076,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 31987.464909083425, \"min\": 718.7488792238004}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.23936637710209036,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8659121395452318, \"min\": 0.06527490644246826}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.521846501233942,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.148347547383032, \"min\": 6.323523546531507}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017539057277441703,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002148542972748216, \"min\": 0.00024166337161137002}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1432.2646228084345,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 20911.675544873655, \"min\": 678.3096157539974}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2809555811512036,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9049213813532707, \"min\": 0.0729395421463255}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 11.153569766373993,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.23249685887956, \"min\": 8.449645128506887}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002945001726875964,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.004208788344699682, \"min\": 0.000659500604201373}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67717700+Gitter499@users.noreply.github.com",
            "name": "Rafayel Amirkhanyan",
            "username": "Gitter499"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4dd3e908130786dcafabbe2e4025fbf58d13d213",
          "message": "Fail gracefully when shadow memory reservation fails (#262)",
          "timestamp": "2026-06-30T11:34:00-04:00",
          "tree_id": "2937f208cc8f7223533843eb2e5c8e6b76a5baa9",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/4dd3e908130786dcafabbe2e4025fbf58d13d213"
        },
        "date": 1782841928690,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1557.3524572115896,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 33993.45054054116, \"min\": 626.2207094038367}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.23741261976601186,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.894922193334424, \"min\": 0.06495705692983693}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.652209714754299,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.409814218458301, \"min\": 5.4354305670252865}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.001769784696671965,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0022151648495792246, \"min\": 0.00023693167156823872}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1485.824521724856,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 28097.311401862004, \"min\": 713.144035629078}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2852137097546972,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8782519532881088, \"min\": 0.07377750961896581}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.92788493096392,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.96948204557039, \"min\": 8.385088592342587}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002938103184418046,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003947129805441583, \"min\": 0.0006715567728559626}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "distinct": true,
          "id": "37ee2e15ad12066ca6bd4bf165f468e0db531e9d",
          "message": "Remove and .gitignore .idea.",
          "timestamp": "2026-06-30T14:20:52-04:00",
          "tree_id": "5abdce579a30a632b39b6ecde6e9d3af70f460b9",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/37ee2e15ad12066ca6bd4bf165f468e0db531e9d"
        },
        "date": 1782848336019,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1577.7075863742612,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 35216.60016542916, \"min\": 709.38547546242}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2406660232076306,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8842511035199614, \"min\": 0.06630774648105138}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.178462264689976,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.589088979726338, \"min\": 5.996835056134633}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0016701162506986748,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002099363994002555, \"min\": 0.00024021989387104504}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1526.5654177822626,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 31806.67392276901, \"min\": 698.2260313719352}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2655552754565187,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9132911068523648, \"min\": 0.06979085984693577}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.961409831972965,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.14217562216035, \"min\": 7.95876135117046}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002742282860087224,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003620048705473489, \"min\": 0.000664912745092868}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "111544848+vnt1c@users.noreply.github.com",
            "name": "Ryan Hung",
            "username": "vnt1c"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "565e466f8dc6df89ff5cc75b93a8850a8e3508e2",
          "message": "Re-implemented tree pruning for GC (#256)\n\n* Re-implemented  with one pass rather than a DFS\n\n* rust fmt\n\n* fixed linting errors\n\n* Modified remove_useless_children_dead to deal with root case, remove_dead_tags now take &[BorTag] type\n\n* Added a to-do comment",
          "timestamp": "2026-06-30T16:13:11-04:00",
          "tree_id": "57872076a8d0733768d2dffb3d50e7bfc22961e3",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/565e466f8dc6df89ff5cc75b93a8850a8e3508e2"
        },
        "date": 1782855216553,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1607.7349252477113,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 35404.09746653717, \"min\": 748.356843346929}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2425730758542488,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9070894097571268, \"min\": 0.06722841602398433}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.184553867606822,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.696649901248101, \"min\": 6.113704177047331}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0016442873818219611,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.001965118314296025, \"min\": 0.00024278760413990407}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1512.5945372149738,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 31831.96110835387, \"min\": 662.2932634625207}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2694914939358915,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9776379765482005, \"min\": 0.06964538621665817}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.685819277804356,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32.701231707229915, \"min\": 7.4473477386866325}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.00276278297822519,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003630332336454176, \"min\": 0.0006520843865250158}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d4069ed0979986aaaed2490e524412447c36b18c",
          "message": "Allocate slots for protected tags from a dedicated region. (#258)\n\n* Allocate slots for protected tags from a dedicated region.\n\n* Only remove protectors for concrete / resolved tags.",
          "timestamp": "2026-06-30T16:28:41-04:00",
          "tree_id": "37703817e67321dad3f1e27a9d9f356dc2b2f6aa",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/d4069ed0979986aaaed2490e524412447c36b18c"
        },
        "date": 1782859997322,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1554.7740095072406,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 33185.97867954374, \"min\": 642.9125926849639}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2378254756723489,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8746494818116494, \"min\": 0.0644291663216578}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.428380858703074,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.712830711371376, \"min\": 5.2386136954590485}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017222317641492273,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002258409873496311, \"min\": 0.00023890967450238796}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1476.8489005812949,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 29570.554001561468, \"min\": 366.73579262051794}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2597236028465949,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.904663308197074, \"min\": 0.06871045077167004}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.796770968217686,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.91575481833938, \"min\": 4.613052616112737}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002736433607650338,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0036150925362765877, \"min\": 0.0006495487872232586}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "032a4fca7039e67db700a1bc3e9d7d1330517fae",
          "message": "Update to rolling-1.98.0-dev-46c2f6f (#263)\n\nUpdates our rust fork to [rolling-1.98.0-dev-46c2f6f](https://github.com/BorrowSanitizer/rust/releases/tag/rolling-1.98.0-dev-46c2f6f), fixing a bug in how we branched to handle retagging enums.",
          "timestamp": "2026-06-30T18:00:04-04:00",
          "tree_id": "a7d7d2e1bb1c60dc3fa7123026dc8c7d73981919",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/032a4fca7039e67db700a1bc3e9d7d1330517fae"
        },
        "date": 1782864785681,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1520.9585843164855,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37137.622963166286, \"min\": 690.8080336393577}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.24201367931745518,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.881613161002731, \"min\": 0.06755292469232917}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.375412671219858,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.721303390183031, \"min\": 6.145312001906342}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.001806839136445618,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002202179255249525, \"min\": 0.00024490166802454877}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 2051.364349952032,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 38452.64459820002, \"min\": 878.1205850365756}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.3050926908308104,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.7990342111669316, \"min\": 0.06101048053268568}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 9.095651261308909,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 28.488749523585557, \"min\": 6.219644184012952}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0019287247545022033,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0024760874536197326, \"min\": 0.00027251553845707263}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "032a4fca7039e67db700a1bc3e9d7d1330517fae",
          "message": "Update to rolling-1.98.0-dev-46c2f6f (#263)\n\nUpdates our rust fork to [rolling-1.98.0-dev-46c2f6f](https://github.com/BorrowSanitizer/rust/releases/tag/rolling-1.98.0-dev-46c2f6f), fixing a bug in how we branched to handle retagging enums.",
          "timestamp": "2026-06-30T22:00:04Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/032a4fca7039e67db700a1bc3e9d7d1330517fae"
        },
        "date": 1782878260429,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1538.895235542518,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 34907.539648198, \"min\": 628.7356762105828}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.23453397082354285,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8691345216801089, \"min\": 0.06469903875165178}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.412098666393839,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.65617188325846, \"min\": 5.703270696111744}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017367495875852167,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0020865560682761875, \"min\": 0.00025061515207662585}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1541.4275011879365,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 34906.4958426543, \"min\": 692.4741396680013}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2660872033147391,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9199089552521591, \"min\": 0.07014898960426848}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.661106401403586,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 35.95019176415993, \"min\": 7.95348079379469}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0027179485704663655,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.00365980724696321, \"min\": 0.0006598147145345953}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1f571b0c8520274506de5383d0252113186439ac",
          "message": "Implement deferred reference counting (#252)\n\n* Allocate slots for protected tags from a dedicated region.\n\n* Only remove protectors for concrete / resolved tags.\n\n* Lock the tree once.\n\n* Clippy.\n\n* New allocations should evict exposed provenance.\n\n* Ensure that allocations happen under the global exposed provenance lock.\n\n* fmt\n\n* Add support for deferred reference counting.\n\n* Enable garbage collection in Miri for benchmarks.\n\n* Silence false positive warnings for interceptors.\n\n* Patch tests for GC nondeterminism.\n\n* ConcreteTagSet -> BorTagSet, + docs.\n\n* Added missing header.\n\n* Update docs.\n\n* Ensure that we acquire the provenance of heap allocations.\n\n* Only add stack allocation metadata objects to the free list immediately on deallocation.\n\n* clippy\n\n* Ensure that protectors are removed, even for failing protector end accesses.\n\n* Ensure that provenance values on the shadow stack remain above the frame pointer.",
          "timestamp": "2026-07-01T19:34:49-04:00",
          "tree_id": "59f17a8df2db8d857fd9e6b0ad1a76aabda9d255",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/1f571b0c8520274506de5383d0252113186439ac"
        },
        "date": 1782951274305,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 371.4940724138803,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1647.2587311452821, \"min\": 261.78819141052725}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11120414043455648,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.3522042563102754, \"min\": 0.08947653715941588}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.759235926003882,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 17.813958704663474, \"min\": 6.279569571780867}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0023791742189882017,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0035355212713537292, \"min\": 0.002024292285588117}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 486.6734975057014,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2212.306389115194, \"min\": 317.7000967959427}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14926807750748355,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.43460863600021793, \"min\": 0.12105486142044736}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 9.767848265432628,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 29.238134064898723, \"min\": 7.213906874247668}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.003089806352487643,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.005743845259254225, \"min\": 0.002682745109556124}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "1f571b0c8520274506de5383d0252113186439ac",
          "message": "Implement deferred reference counting (#252)\n\n* Allocate slots for protected tags from a dedicated region.\n\n* Only remove protectors for concrete / resolved tags.\n\n* Lock the tree once.\n\n* Clippy.\n\n* New allocations should evict exposed provenance.\n\n* Ensure that allocations happen under the global exposed provenance lock.\n\n* fmt\n\n* Add support for deferred reference counting.\n\n* Enable garbage collection in Miri for benchmarks.\n\n* Silence false positive warnings for interceptors.\n\n* Patch tests for GC nondeterminism.\n\n* ConcreteTagSet -> BorTagSet, + docs.\n\n* Added missing header.\n\n* Update docs.\n\n* Ensure that we acquire the provenance of heap allocations.\n\n* Only add stack allocation metadata objects to the free list immediately on deallocation.\n\n* clippy\n\n* Ensure that protectors are removed, even for failing protector end accesses.\n\n* Ensure that provenance values on the shadow stack remain above the frame pointer.",
          "timestamp": "2026-07-01T23:34:49Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/1f571b0c8520274506de5383d0252113186439ac"
        },
        "date": 1782962037649,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 385.5075181583357,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1615.2253577644444, \"min\": 261.82712164525856}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.1162269923336671,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.35077198219243283, \"min\": 0.09587065419895496}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.494711121058481,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.733544850480655, \"min\": 5.760723946321098}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0023102185136684014,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0033756965489927155, \"min\": 0.0019983289483382293}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 520.161429055372,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2069.6016538524295, \"min\": 286.72485404347736}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.18563830090355873,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.4769914423891314, \"min\": 0.14381748258439817}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.139046338558014,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.18834103782277, \"min\": 7.860735871539554}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004798753440576842,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.008252769538586235, \"min\": 0.0037543341724433064}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "1f571b0c8520274506de5383d0252113186439ac",
          "message": "Implement deferred reference counting (#252)\n\n* Allocate slots for protected tags from a dedicated region.\n\n* Only remove protectors for concrete / resolved tags.\n\n* Lock the tree once.\n\n* Clippy.\n\n* New allocations should evict exposed provenance.\n\n* Ensure that allocations happen under the global exposed provenance lock.\n\n* fmt\n\n* Add support for deferred reference counting.\n\n* Enable garbage collection in Miri for benchmarks.\n\n* Silence false positive warnings for interceptors.\n\n* Patch tests for GC nondeterminism.\n\n* ConcreteTagSet -> BorTagSet, + docs.\n\n* Added missing header.\n\n* Update docs.\n\n* Ensure that we acquire the provenance of heap allocations.\n\n* Only add stack allocation metadata objects to the free list immediately on deallocation.\n\n* clippy\n\n* Ensure that protectors are removed, even for failing protector end accesses.\n\n* Ensure that provenance values on the shadow stack remain above the frame pointer.",
          "timestamp": "2026-07-01T23:34:49Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/1f571b0c8520274506de5383d0252113186439ac"
        },
        "date": 1783046879462,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 383.74880062996584,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1659.8365921747113, \"min\": 277.99583071544146}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11596083452698318,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.34829098621354887, \"min\": 0.0945979368839869}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.611185905841937,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 18.114756693956373, \"min\": 6.115184906536259}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0023523645774114394,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003657387205913793, \"min\": 0.0019528468007314012}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 523.4056538781358,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2497.1132233279122, \"min\": 362.9048859587488}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.18169666422780484,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.4996057519403349, \"min\": 0.14810498594738086}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.408315359046467,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 41.12026285394736, \"min\": 9.410190687668692}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0047695851485414845,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.008400156330181655, \"min\": 0.003795968104391787}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "1f571b0c8520274506de5383d0252113186439ac",
          "message": "Implement deferred reference counting (#252)\n\n* Allocate slots for protected tags from a dedicated region.\n\n* Only remove protectors for concrete / resolved tags.\n\n* Lock the tree once.\n\n* Clippy.\n\n* New allocations should evict exposed provenance.\n\n* Ensure that allocations happen under the global exposed provenance lock.\n\n* fmt\n\n* Add support for deferred reference counting.\n\n* Enable garbage collection in Miri for benchmarks.\n\n* Silence false positive warnings for interceptors.\n\n* Patch tests for GC nondeterminism.\n\n* ConcreteTagSet -> BorTagSet, + docs.\n\n* Added missing header.\n\n* Update docs.\n\n* Ensure that we acquire the provenance of heap allocations.\n\n* Only add stack allocation metadata objects to the free list immediately on deallocation.\n\n* clippy\n\n* Ensure that protectors are removed, even for failing protector end accesses.\n\n* Ensure that provenance values on the shadow stack remain above the frame pointer.",
          "timestamp": "2026-07-01T23:34:49Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/1f571b0c8520274506de5383d0252113186439ac"
        },
        "date": 1783133145992,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 383.12365154120977,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1716.7612851836373, \"min\": 290.59503892690293}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11626749302263205,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.35536193282775835, \"min\": 0.09359003008301603}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.571280357191092,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 18.240043297474408, \"min\": 5.749896790998193}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0023522153486765104,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003588479522284295, \"min\": 0.0020782032807085903}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 519.8583300029637,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2492.0111418017186, \"min\": 358.2402174107392}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.18497505525737942,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.5072017646033072, \"min\": 0.1536973408211645}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.080357662198903,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 40.51046823281144, \"min\": 9.999053305244773}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004771192958399791,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.008245140091040189, \"min\": 0.003970444506498039}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "1f571b0c8520274506de5383d0252113186439ac",
          "message": "Implement deferred reference counting (#252)\n\n* Allocate slots for protected tags from a dedicated region.\n\n* Only remove protectors for concrete / resolved tags.\n\n* Lock the tree once.\n\n* Clippy.\n\n* New allocations should evict exposed provenance.\n\n* Ensure that allocations happen under the global exposed provenance lock.\n\n* fmt\n\n* Add support for deferred reference counting.\n\n* Enable garbage collection in Miri for benchmarks.\n\n* Silence false positive warnings for interceptors.\n\n* Patch tests for GC nondeterminism.\n\n* ConcreteTagSet -> BorTagSet, + docs.\n\n* Added missing header.\n\n* Update docs.\n\n* Ensure that we acquire the provenance of heap allocations.\n\n* Only add stack allocation metadata objects to the free list immediately on deallocation.\n\n* clippy\n\n* Ensure that protectors are removed, even for failing protector end accesses.\n\n* Ensure that provenance values on the shadow stack remain above the frame pointer.",
          "timestamp": "2026-07-01T23:34:49Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/1f571b0c8520274506de5383d0252113186439ac"
        },
        "date": 1783220124893,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 388.25743375052275,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1626.479451430272, \"min\": 272.00305757992635}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11802959624290434,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.35405783105033456, \"min\": 0.09683688109051874}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.776304621441655,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 18.287983083954554, \"min\": 5.554797740394098}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0024077975660253023,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003889671631851089, \"min\": 0.0020443383581630788}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 523.6265348040167,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2485.2725071737977, \"min\": 298.30759705927534}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.17957574475840424,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.4940963313963973, \"min\": 0.1487876369295214}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.484306615049967,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 42.09834202234772, \"min\": 8.255839674460821}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0047366139246451605,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.008408342016593856, \"min\": 0.003743048214757129}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "890b2b3b938cf31807bc23723a947b918ff62282",
          "message": "Set `CLANG_PATH` and `LIBCLANG_PATH` in `cargo-bsan` (#270)\n\n* Set `CLANG_PATH` and `LIBCLANG_PATH` to ensure that crates with bindgen use our version of `clang`\n\n* fmt",
          "timestamp": "2026-07-05T10:54:37-04:00",
          "tree_id": "3f8a2b0465dcdacb6f2566007c21a5caa3d52e8f",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/890b2b3b938cf31807bc23723a947b918ff62282"
        },
        "date": 1783265848747,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 378.2475217051335,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1679.607707455797, \"min\": 281.3482436874645}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11465316027776361,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.35908130661971255, \"min\": 0.09317112411476527}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.958313439808378,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 17.734787221022398, \"min\": 6.6406736557851405}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002480381279385517,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003471021296946072, \"min\": 0.0021473891420736987}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 493.68797731169684,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2295.2826427037708, \"min\": 291.3791795541573}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.19169151248272573,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.5182142962906441, \"min\": 0.15676559967312437}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.5575637127856,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 42.751158943771095, \"min\": 9.077355166977899}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.005387429812245757,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.009652084381886316, \"min\": 0.004436557455952731}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "890b2b3b938cf31807bc23723a947b918ff62282",
          "message": "Set `CLANG_PATH` and `LIBCLANG_PATH` in `cargo-bsan` (#270)\n\n* Set `CLANG_PATH` and `LIBCLANG_PATH` to ensure that crates with bindgen use our version of `clang`\n\n* fmt",
          "timestamp": "2026-07-05T14:54:37Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/890b2b3b938cf31807bc23723a947b918ff62282"
        },
        "date": 1783307201622,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 383.82426257687666,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1658.4172927177842, \"min\": 281.1318159361851}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11511762423799925,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.3575482582084587, \"min\": 0.0926611755512554}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.905684774225471,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 17.19768717365353, \"min\": 6.427108355185953}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002425779148527225,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0035816843671052775, \"min\": 0.002010270916641325}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 518.138414127073,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2466.0380680346175, \"min\": 356.2354363060067}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.18254232622118433,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.4919818244979034, \"min\": 0.14931512982006775}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.565371253618242,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 41.427651706372984, \"min\": 10.048666694686258}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.00488998585820226,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.008366232391518912, \"min\": 0.003983975244148926}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3ec4ad00796e2498adeaeca5f231f571436d9ea2",
          "message": "Merge pull request #271 from BorrowSanitizer/bench\n\nadd more benchmarking crates",
          "timestamp": "2026-07-06T14:55:45-04:00",
          "tree_id": "ab1bcb95be8001be3bdcd98042245862aed63988",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/3ec4ad00796e2498adeaeca5f231f571436d9ea2"
        },
        "date": 1783374648852,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 382.38063088901424,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1610.252004979393, \"min\": 205.0224879598536}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11474826302204881,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.3538174458282966, \"min\": 0.07967069611007428}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.475575841320167,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 17.184117252850086, \"min\": 4.472686396419755}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002299026981563252,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0035282680764816988, \"min\": 0.0011791645548064477}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 791.1683303021822,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 18264.124738868282, \"min\": 285.36799194588633}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.9100951173385572,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 16.446774314915018, \"min\": 0.10488359307165576}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 9.839513731530683,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 44.92454332119101, \"min\": 5.645659645030549}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.010792823848685337,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.16866417086975966, \"min\": 0.002097595762665971}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 5696.866858974408,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 10973.323631012818, \"min\": 989.8918456949517}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.6826022266526924,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 1.1092077013644468, \"min\": 0.354813777376166}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 27.935599194308516,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 42.419160518324844, \"min\": 12.753241018566705}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.004359745981685006,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.005038114607077101, \"min\": 0.003564546141095626}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 523.909993677434,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2490.2755360825895, \"min\": 236.57409785410914}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.18756933082186936,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.5101664154506526, \"min\": 0.15602479526058544}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.26455766320291,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 40.8771912090622, \"min\": 6.776425151055728}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004880460202286438,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.008374242050991486, \"min\": 0.0039570793944908155}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1231.1328255146636,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24348.54605339511, \"min\": 240.65692757071434}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1.3795618039423077,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 28.30245139116766, \"min\": 0.1546118889719825}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 21.886651250203908,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 136.75478636237315, \"min\": 6.500347101132201}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.024611841415120284,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.4135902970819166, \"min\": 0.00382338519311255}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 7974.919299250945,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 15384.397177026405, \"min\": 1293.6021789817084}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 1.0066253940794627,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 1.5435250919696037, \"min\": 0.5570206443556788}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 56.30530964658539,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 91.9646830192346, \"min\": 20.153463452516913}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008929929549396752,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.00943575919606532, \"min\": 0.008425297605358423}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "3ec4ad00796e2498adeaeca5f231f571436d9ea2",
          "message": "Merge pull request #271 from BorrowSanitizer/bench\n\nadd more benchmarking crates",
          "timestamp": "2026-07-06T18:55:45Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/3ec4ad00796e2498adeaeca5f231f571436d9ea2"
        },
        "date": 1783399898354,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 379.77288392949015,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1670.675270189168, \"min\": 276.00435966787677}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11624196917863569,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.3540580285137579, \"min\": 0.09471688441871733}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.744621305587887,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 17.267310300504228, \"min\": 6.1904158953953585}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002429100955086102,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003509679794767445, \"min\": 0.002087326815976761}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 800.7160252117687,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 18628.18181974188, \"min\": 283.08777608843394}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.8993427821592717,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 16.442433679880246, \"min\": 0.10329758350185665}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 10.105716249418865,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 44.66253832968049, \"min\": 6.146331407790491}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.010395862205235449,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.1593747011070466, \"min\": 0.002191337043058304}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 5814.1455956263635,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 11160.473656528293, \"min\": 934.588768358136}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.6853120801938217,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 1.091976237026234, \"min\": 0.36854101179275633}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 27.958619636498288,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 42.005457939339955, \"min\": 12.14552311880369}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.004428598678729296,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.005189540138684696, \"min\": 0.0035342494099657625}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 495.0439835439037,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2363.8986795268556, \"min\": 336.98416628073466}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.19027128524784215,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.5175913473967415, \"min\": 0.1477854167116183}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.68119565086401,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 40.04964809058536, \"min\": 10.115577693420597}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.005394147021388652,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.009223253856399837, \"min\": 0.004526678335460233}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1186.140361590913,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24669.054381560796, \"min\": 324.80691284923756}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1.416818063724922,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 29.255721615361697, \"min\": 0.15637649872336884}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 22.38033518277937,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 148.64560451191116, \"min\": 9.856088435544054}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.026628689133376415,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.4395561705010338, \"min\": 0.004632402470673878}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 8124.075334325126,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 16130.805267900565, \"min\": 1239.1152279682399}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 1.0527441523024816,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 1.614404127414232, \"min\": 0.5554335753783941}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 59.93795065353919,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 101.14648269119877, \"min\": 20.170038234857138}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.00976180883314803,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.010412573444008465, \"min\": 0.009041222478296237}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "111544848+vnt1c@users.noreply.github.com",
            "name": "Ryan Hung",
            "username": "vnt1c"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ed2a742d9e51fa03617942cce9970b69e1895f2a",
          "message": "Retain unprunable dead tags for future GC passes (#269)\n\n* Implemented deferred tree pruning; unpruned tags remain in the dead tags list, and are considered in the next GC pass.\n\n* Added 3 basic tree pruning tests",
          "timestamp": "2026-07-07T16:03:39-04:00",
          "tree_id": "46cbccab224d477226b098b84af6ffb0f72f3934",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/ed2a742d9e51fa03617942cce9970b69e1895f2a"
        },
        "date": 1783464974953,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 375.3024366747752,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1583.9385450864027, \"min\": 275.4082789575756}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11330037929425694,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.3116181125450101, \"min\": 0.09321664254740497}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.910115770371997,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 17.688678288609825, \"min\": 5.91840137407685}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0024354954639712206,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0037362588235581584, \"min\": 0.0020495236333568567}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 789.9602960413326,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 18998.455613988684, \"min\": 275.05022854305037}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.8696399875429949,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 16.247264082423786, \"min\": 0.09679848643840112}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 10.052727906529395,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 43.66972777501944, \"min\": 5.959560379151825}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.010461859458369296,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.16896273110451657, \"min\": 0.002074084527712492}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 5366.272768019219,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 10889.434358681021, \"min\": 899.0699912535057}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.6361597218535056,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 1.0167625244944483, \"min\": 0.34528884730859144}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 27.600042807844122,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 43.01301658858431, \"min\": 12.831574040441566}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.004366013080784115,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.005457051803445718, \"min\": 0.003394564902516483}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 516.9057521715682,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2322.850933982754, \"min\": 326.0016105098477}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.18638711804415928,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.4788035182350605, \"min\": 0.1561007133075488}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.27481548380578,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 40.91765491438582, \"min\": 8.359927848391456}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004868277086569817,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.00877227287201502, \"min\": 0.003715321264614867}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1232.7062137666783,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24438.01126103271, \"min\": 336.29342593331154}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1.3824242184287208,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 28.364257216748214, \"min\": 0.16327436340551324}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 21.85345209094774,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 137.60473422410305, \"min\": 9.277018634771265}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.024846726192261435,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.4141548428343512, \"min\": 0.0042258235124868655}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 7410.487686979505,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 14800.725119914263, \"min\": 1285.3715088133526}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.9573498617295569,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 1.4461823169330343, \"min\": 0.5490179103946078}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 55.76629293686796,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 91.03708844227494, \"min\": 20.074258866575192}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008876340595504024,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.009503606684162273, \"min\": 0.00794010787797425}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67717700+Gitter499@users.noreply.github.com",
            "name": "Rafayel Amirkhanyan",
            "username": "Gitter499"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8d32042fc4008ba07a75d8cae98986ee17a83df4",
          "message": "Added stack-safe unchecked accesses (#253)\n\n* feat(#251): WIP: Added stack-safe unchecked accesses\n\n* feat(#251): Finished implementation with correct SSGI call\n\n* fix(#251): skip instrumenting SafeStack-safe allocas\n\nInstead of marking individual accesses as safe, ignore allocas that\nSafeStack deems safe entirely: no alloc/dealloc tracking, no retags,\nand no lifetime handling for them. Any access that still reaches the\nread/write checks now takes the full borrow-tracking path (checked =\nfalse). The runtime's checked-flag plumbing and unchecked fast paths\nare retained for future use.\n\n* style(#251): satisfy rustfmt and clang-format\n\nReformat the checked-flag plumbing introduced during the rebase onto\nmain so `cargo fmt --check` and clang-format pass in CI.",
          "timestamp": "2026-07-07T21:09:04-04:00",
          "tree_id": "544a275ea37ddbb28ada0627f820604af4343285",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/8d32042fc4008ba07a75d8cae98986ee17a83df4"
        },
        "date": 1783483052376,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 350.2259515316996,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1420.0634217869742, \"min\": 267.63391271242745}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.10798958433135615,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.28808830885899855, \"min\": 0.0904951751426126}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.242661448156394,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 10.889410728700375, \"min\": 5.90413852525084}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022948045836980037,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0027561482545313265, \"min\": 0.001938173601159938}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 710.4950091552023,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 17778.647366329664, \"min\": 268.72877878152707}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.7351237058928866,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 12.003975130153334, \"min\": 0.09939290188421052}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.879927442775018,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24.867592519100608, \"min\": 6.0426068532239166}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0060143533519031265,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.06309165842930929, \"min\": 0.002127164235463636}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 4695.21524507196,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9203.872631825381, \"min\": 850.5614542972731}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.5667062219024707,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.9231578984231785, \"min\": 0.31218033752428964}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.166739324489633,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.75055080382856, \"min\": 10.126088050090976}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003124419958448022,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004446627635345151, \"min\": 0.0021712139057864966}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 468.40843900933885,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2066.3298687239667, \"min\": 230.67955000773796}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.16345010743843993,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.4182496079177096, \"min\": 0.13756248903544033}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.170944294740005,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 35.182650071606915, \"min\": 7.172655440329932}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004710664434537079,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.007121384547880874, \"min\": 0.003983289175715336}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1073.5397503360057,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22886.231411724555, \"min\": 312.77322339354913}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1.0759915069440467,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 18.386620270086024, \"min\": 0.14219330184531326}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 19.412123376238117,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 106.08521462207788, \"min\": 8.4789448519836}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.01953535500588507,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.2932362781022446, \"min\": 0.004008493517895848}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 6377.342130134326,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 13095.811359465746, \"min\": 1104.828973446691}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.7721253409390179,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 1.196925316530456, \"min\": 0.45649695394162704}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 47.721344626247415,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 76.44657239069977, \"min\": 18.58214542338407}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007386498729758118,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.00815831203533332, \"min\": 0.00664804237852688}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Rafayel Amirkhanyan",
            "username": "Gitter499",
            "email": "67717700+Gitter499@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "8d32042fc4008ba07a75d8cae98986ee17a83df4",
          "message": "Added stack-safe unchecked accesses (#253)\n\n* feat(#251): WIP: Added stack-safe unchecked accesses\n\n* feat(#251): Finished implementation with correct SSGI call\n\n* fix(#251): skip instrumenting SafeStack-safe allocas\n\nInstead of marking individual accesses as safe, ignore allocas that\nSafeStack deems safe entirely: no alloc/dealloc tracking, no retags,\nand no lifetime handling for them. Any access that still reaches the\nread/write checks now takes the full borrow-tracking path (checked =\nfalse). The runtime's checked-flag plumbing and unchecked fast paths\nare retained for future use.\n\n* style(#251): satisfy rustfmt and clang-format\n\nReformat the checked-flag plumbing introduced during the rebase onto\nmain so `cargo fmt --check` and clang-format pass in CI.",
          "timestamp": "2026-07-08T01:09:04Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/8d32042fc4008ba07a75d8cae98986ee17a83df4"
        },
        "date": 1783492840676,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 347.5424853993754,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1370.2840117848568, \"min\": 270.86327188433535}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.10608265250629394,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2838159454915337, \"min\": 0.09035204382510814}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.360142093233803,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 10.621518747504519, \"min\": 6.002476819222263}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0023063620199959218,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0027844664464810156, \"min\": 0.0020505633403432866}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 706.6564772174447,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 18117.263933782142, \"min\": 142.58958942995957}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.7231112219724551,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 11.380068006965566, \"min\": 0.09711127849792088}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.897447026737192,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24.184179683158906, \"min\": 3.408823145040289}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.006000449336907736,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.06277626142933074, \"min\": 0.002076593399434711}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 4763.367428867628,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9783.71200007479, \"min\": 837.3753075889884}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.5623097912832714,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.9084680789962866, \"min\": 0.3034008411963765}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 17.785748019431768,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.523014614792075, \"min\": 9.742737498820926}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003008253082291588,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004184263691547164, \"min\": 0.0020466079322320244}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 465.80220664695315,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2085.8154932700545, \"min\": 277.1558779993242}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.1661946475334302,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.42410110522956945, \"min\": 0.13937602944558344}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.04983137368351,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.01481738847312, \"min\": 8.725156581490204}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004765227752250341,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.007425549022728629, \"min\": 0.00405529453951299}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1060.4169674553632,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22301.618020173075, \"min\": 329.0519198757221}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1.095067830620019,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 18.677077375973884, \"min\": 0.145356151272356}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 19.279205793216654,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 108.0459471825885, \"min\": 9.674751293856062}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.02001708807150558,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.3144835532052686, \"min\": 0.004118872385184049}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 6160.788451077242,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 12066.386403329048, \"min\": 1094.129116715798}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.7788763890932192,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 1.1770621223305204, \"min\": 0.4616573126757914}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 47.633480217093435,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 76.76549433257732, \"min\": 18.74823087944229}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007696755657634866,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008475443020565764, \"min\": 0.006958900437629234}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "fe64e8431405829189fb21e5f45d8f49b47e457c",
          "message": "remove env_logger and log (#274)",
          "timestamp": "2026-07-08T15:10:15-04:00",
          "tree_id": "6672488129e33cfe1a0e5c305b7c5ac1f744e59b",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fe64e8431405829189fb21e5f45d8f49b47e457c"
        },
        "date": 1783547946906,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 355.43489148563776,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1421.2865138043326, \"min\": 271.6525922652083}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.10708129822239892,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.28883034762527626, \"min\": 0.08869513485333534}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.388306505103421,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.128984754423588, \"min\": 6.395729597751973}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002280647328318873,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0027756404239011457, \"min\": 0.0019849408802271352}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 707.0027800907924,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 17498.296852438005, \"min\": 271.2223808594017}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.7266081777996802,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 11.976101072991368, \"min\": 0.09616350299688786}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 8.186945077305383,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.426251994521166, \"min\": 6.176719745334458}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.006031766217440915,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.06486254045182527, \"min\": 0.002045930201344923}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 4665.755466051544,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9033.13551006438, \"min\": 888.8389221393156}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.558228101267362,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.9057929155768719, \"min\": 0.3129610930856775}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.00787295645771,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.147760346415485, \"min\": 10.113621653658079}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0029491369839398027,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.0038870229834964756, \"min\": 0.002193493945044543}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 469.2910527600543,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2088.05867278117, \"min\": 331.69976737048034}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.16213375433470478,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.41856307869307136, \"min\": 0.13541938270225368}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.030235893506335,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 34.43097421559415, \"min\": 9.028561190037959}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004608334577968827,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006901882000703331, \"min\": 0.003932630115766874}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1071.090518753223,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22871.818583133252, \"min\": 291.189093086175}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1.061827947363525,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 18.692234250110236, \"min\": 0.13744249639355346}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 19.09326308951133,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 107.26027603037751, \"min\": 8.91625400326012}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.01866871840210746,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.29315339902827636, \"min\": 0.00406441658510957}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 6339.459014457526,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 12608.476021939912, \"min\": 1084.6050084392384}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.7808907732865151,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 1.212569218318557, \"min\": 0.45683122608412446}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 47.570496497696034,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 77.24135828790617, \"min\": 18.128931750242618}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007408815284085928,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008000843476863887, \"min\": 0.006604533702429318}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "fe64e8431405829189fb21e5f45d8f49b47e457c",
          "message": "remove env_logger and log (#274)",
          "timestamp": "2026-07-08T19:10:15Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fe64e8431405829189fb21e5f45d8f49b47e457c"
        },
        "date": 1783572688321,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 351.06997877707454,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1407.3268209924454, \"min\": 275.5692790125822}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.1067530125310448,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2908565698883269, \"min\": 0.08880587089987518}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.336020825072333,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.349516300559982, \"min\": 6.332694036483711}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002290221584373341,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0026634715244762642, \"min\": 0.0019855570070967305}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 701.5175744653995,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 17339.600171953818, \"min\": 260.61864855360477}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.7161627115119328,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 11.27533510886826, \"min\": 0.09669241814757361}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 8.016021844447195,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.571058079482984, \"min\": 6.127124780363555}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.005994588518670174,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.06351567449119302, \"min\": 0.0021187041867291815}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 4664.802180472862,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9219.136190539695, \"min\": 851.6791204571622}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.5578619284293699,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.91812284527271, \"min\": 0.31315806127357754}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.20303654749762,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.517592105123878, \"min\": 10.530591636383297}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031216558792791682,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004259877557001771, \"min\": 0.002088296200281383}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 463.9007291547099,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 2036.8573062353244, \"min\": 226.21746453400218}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.16387738244294428,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.41556754266180107, \"min\": 0.12709040620989376}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 12.77915460357937,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 34.045109283299, \"min\": 6.740294898454745}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.00461902072404218,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006946015492200841, \"min\": 0.003578136495610863}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1071.9809726896394,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23080.102578789134, \"min\": 262.6468354775269}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 1.0617413196567291,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 18.773034703456617, \"min\": 0.1282865761687526}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 19.47663613702604,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 109.2379513638676, \"min\": 8.120646366713414}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.019413887553695264,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.3000271321461502, \"min\": 0.003472613211703611}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 6343.187540312428,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 12952.031938263477, \"min\": 1099.9596435711082}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.7827881141961162,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 1.2471672595912338, \"min\": 0.42014821383970635}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 47.356279571053335,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 76.93357949305448, \"min\": 18.11292083924968}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007398090679604863,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008355340739083691, \"min\": 0.00664332892972881}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "87315f8a75dd36d824b974f7dd20abdf4f4a2e7e",
          "message": "Merge pull request #278 from BorrowSanitizer/fixbench",
          "timestamp": "2026-07-10T10:55:28-04:00",
          "tree_id": "63ebe27ada63958f1b4e53e8c22883136c0df323",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/87315f8a75dd36d824b974f7dd20abdf4f4a2e7e"
        },
        "date": 1783703610936,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 359.70667588755134,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1160.4379208384266, \"min\": 286.07705322850524}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.1091877642018557,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.22883584767944568, \"min\": 0.0968699952027877}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.633722124669362,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.74773282654423, \"min\": 6.675463134904543}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.00237161417394361,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0030196715201443987, \"min\": 0.0019435503082231619}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 583.7611030872108,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 21485.987559771504, \"min\": 278.9852922297765}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1332260704101615,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.8980767286439577, \"min\": 0.10317820154953956}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.373747779435078,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.0631542463597, \"min\": 6.33090341879297}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002443315384146951,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002853631823358128, \"min\": 0.002037403970488335}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3715.3379444572306,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7319.92248317754, \"min\": 656.0047928190351}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4411418612076197,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.713742879869892, \"min\": 0.23811879460289748}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.430004369730202,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.49868337018806, \"min\": 10.685270372131193}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031539144975672147,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004183021215333265, \"min\": 0.00214829079984773}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 382.8262559824035,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1291.2719872576547, \"min\": 300.595828038073}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.13516226959883962,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.26779526636743667, \"min\": 0.11830915600924331}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.069312038275086,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 35.27423690565423, \"min\": 9.55618516204463}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004671643022495495,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.007132307197957793, \"min\": 0.003788157412987587}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 679.5742668824721,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 28059.67310685763, \"min\": 276.2229039566863}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.16227597884141667,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.977660559992967, \"min\": 0.1287175133639692}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.127390916207773,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 108.23778049407217, \"min\": 9.672450075524255}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004814782136402406,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007628655856720872, \"min\": 0.004204414431051861}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4108.402016600096,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8449.274362868211, \"min\": 698.1615269593009}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.507044248788884,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8058843784705867, \"min\": 0.28501588058001986}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.49917171881654,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 78.24932786149036, \"min\": 17.13843823411347}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007649065051538465,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008495994949269675, \"min\": 0.00705099133489477}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6e77ac3be122109de1dbe1247b7b17c7a0b6a4eb",
          "message": "Merge pull request #272 from BorrowSanitizer/icmccorm/cpy-prov\n\nFixed `byval` and guarded against ABI differences.",
          "timestamp": "2026-07-10T14:23:36-04:00",
          "tree_id": "5e015041f6c07721a1d055a8f81721e162d4cc51",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/6e77ac3be122109de1dbe1247b7b17c7a0b6a4eb"
        },
        "date": 1783716061237,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 357.29602815943224,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1169.8923437985004, \"min\": 225.02449436532984}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.10875756178607146,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23411555168503884, \"min\": 0.0968535332137642}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.69660870445197,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.577331559103833, \"min\": 5.493498283725583}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002397217687953319,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003019994745008583, \"min\": 0.0019502870211105775}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 576.9063908286168,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 21055.12554985449, \"min\": 241.91054046045065}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1306539764785201,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.755826521246675, \"min\": 0.10128144941508761}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.5064594752925045,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.85659140419486, \"min\": 5.234628253625085}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0024790522296683735,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.00272916217902202, \"min\": 0.001989446027991995}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3677.1134188266756,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7360.433342618421, \"min\": 631.8849755305293}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4367575618579768,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7108997861794877, \"min\": 0.2372069987021681}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.301551823579505,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.640048517356604, \"min\": 10.658980247952826}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031541209187546325,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004179954498204174, \"min\": 0.0021386007918431592}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 378.30081742335364,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1346.7224867841073, \"min\": 210.16990089246497}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.1356103658496748,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2705315112739026, \"min\": 0.11466808206847229}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 12.955638607237509,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 38.084729091138236, \"min\": 7.16538298758563}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.00470188369495286,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0074624377952967865, \"min\": 0.0035896318058123307}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 654.8718632826491,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 27071.098790420332, \"min\": 243.46183576309667}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.15956698029690736,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.984529470675825, \"min\": 0.1228305946627007}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 12.967023282131592,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 107.25333885165118, \"min\": 8.417310953421689}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004839240679609633,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007862533154908462, \"min\": 0.0039651404829969235}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4073.1417615918895,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8497.442878239883, \"min\": 584.3213467353972}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.51213455732739,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.829022339011872, \"min\": 0.29109870612316274}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.309931383288905,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 78.34283836819982, \"min\": 16.329874130849962}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007772643589702786,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.00843136629513689, \"min\": 0.006909436379648749}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "6e77ac3be122109de1dbe1247b7b17c7a0b6a4eb",
          "message": "Merge pull request #272 from BorrowSanitizer/icmccorm/cpy-prov\n\nFixed `byval` and guarded against ABI differences.",
          "timestamp": "2026-07-10T18:23:36Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/6e77ac3be122109de1dbe1247b7b17c7a0b6a4eb"
        },
        "date": 1783743244172,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 361.3696790046012,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1183.1884936663025, \"min\": 283.15386752216165}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.1097349948734552,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.22550094868464607, \"min\": 0.09753245471900258}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.3860165929795825,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.324188434219277, \"min\": 6.373050153452267}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022946753644019565,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0028079232064525694, \"min\": 0.001971926335848695}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 581.0516996320387,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 21096.75198081413, \"min\": 290.1896901948808}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1332685176064176,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.8838607994706418, \"min\": 0.10356200911642649}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.274129599559339,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.384120768394343, \"min\": 6.15898178589683}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002397180063784698,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0026877178046113516, \"min\": 0.0020881142502754777}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3683.5970110158005,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7317.2658032109575, \"min\": 663.364955437927}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4390314840407199,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7163605362159698, \"min\": 0.23785555546958326}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.457817599219194,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.07059419667292, \"min\": 10.406307964110944}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003134074378708719,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.0041685206690149235, \"min\": 0.0021432971529087887}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 384.2705975139536,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1345.990223506674, \"min\": 307.4293387894555}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.13275714662974417,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.25640884932928787, \"min\": 0.11620306954864654}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.107252631925352,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 33.86619583924167, \"min\": 10.309280452380474}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004589034247239534,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006827513245021275, \"min\": 0.0038244950179689065}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 667.0510573242366,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 27534.100068660668, \"min\": 284.6403772020689}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.15620801822309863,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9137142215784573, \"min\": 0.12019090662917478}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.033094819545699,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 105.76195328055525, \"min\": 9.792249408415955}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004686713424461289,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0073508178436993725, \"min\": 0.004013066128288979}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4241.460993268214,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8681.713802741257, \"min\": 697.4365614669996}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5163191803098084,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8291249009534675, \"min\": 0.28651327268476057}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.01870372450427,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 78.99310135368425, \"min\": 18.365659796511153}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.00749443651888294,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008341413224206376, \"min\": 0.006935620436184322}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "6e77ac3be122109de1dbe1247b7b17c7a0b6a4eb",
          "message": "Merge pull request #272 from BorrowSanitizer/icmccorm/cpy-prov\n\nFixed `byval` and guarded against ABI differences.",
          "timestamp": "2026-07-10T18:23:36Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/6e77ac3be122109de1dbe1247b7b17c7a0b6a4eb"
        },
        "date": 1783829139604,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 358.8658315483409,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1222.8206205507865, \"min\": 287.4779774512473}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14364939561508813,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.28539908838520134, \"min\": 0.12342760952556507}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.141380915117075,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 35.29521405747112, \"min\": 10.18024814800726}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.005310685938119133,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.008623431448487505, \"min\": 0.004485504644264687}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 626.6350915132865,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 25595.161186409303, \"min\": 280.31285079388874}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.16581728511384317,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9137723025210325, \"min\": 0.1285595710264832}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.538130957176506,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 130.01609614149774, \"min\": 9.969180114869552}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005411359048169775,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.00972141577329198, \"min\": 0.004423463916489223}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4042.6694434562482,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8251.097609439536, \"min\": 662.4586701316817}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.540643810564459,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8489403507270277, \"min\": 0.3117683054443848}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 50.33719190826748,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 81.08166730530421, \"min\": 18.397423279899897}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.00864590866562663,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.009526180835278626, \"min\": 0.008138271925225435}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 366.19936652433375,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1161.6048274520783, \"min\": 295.19552180525426}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11094778146308881,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2487343029554757, \"min\": 0.09851160373027111}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.382931818249748,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.471019087197668, \"min\": 6.425992854489299}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022868318001910957,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0027355699569192866, \"min\": 0.0019847976863391647}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 581.0245112431193,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 20907.395825699536, \"min\": 287.3830402458923}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13328615139571837,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.8325401192508106, \"min\": 0.10493950954515814}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.343721564620472,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.80404987727476, \"min\": 6.384132407887031}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0024176721939220334,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0032485276427468924, \"min\": 0.002086432799398813}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3665.668762448077,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7167.8645851437495, \"min\": 639.8813972354089}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4382416529411484,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7144892271005038, \"min\": 0.24047593937662534}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.597598388299442,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.945582956357384, \"min\": 10.696832603437212}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003165043814690204,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004138027289242072, \"min\": 0.002209777797226374}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "6e77ac3be122109de1dbe1247b7b17c7a0b6a4eb",
          "message": "Merge pull request #272 from BorrowSanitizer/icmccorm/cpy-prov\n\nFixed `byval` and guarded against ABI differences.",
          "timestamp": "2026-07-10T18:23:36Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/6e77ac3be122109de1dbe1247b7b17c7a0b6a4eb"
        },
        "date": 1783916097712,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 363.53824704894174,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1097.7616179358163, \"min\": 281.0955700666822}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11017839716137572,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.24125944462455473, \"min\": 0.09647624925493178}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.313440602731375,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.189397408117701, \"min\": 6.256535264507709}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022652845912163296,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0028830727635313067, \"min\": 0.0019027361169454812}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 590.2201738330259,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 21633.11345516794, \"min\": 292.7058225241116}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13434313386838015,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.902366306275337, \"min\": 0.10237164949462585}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 6.947369391514006,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24.71755450183953, \"min\": 5.997606162870602}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002281749555145597,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002456241587008079, \"min\": 0.0020708405665707907}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3676.0191673502422,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7251.767262614407, \"min\": 657.5372747619015}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.43830062497795585,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7232456380244634, \"min\": 0.23990503831629348}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.452353722606787,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.143327489049064, \"min\": 9.938902439864199}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003082228341790044,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004003507611839834, \"min\": 0.0021999518356869956}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 381.2848638748925,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1345.4146726639558, \"min\": 285.4511601983913}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.1351231421405615,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.26164487117012003, \"min\": 0.11713330585149953}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.080684619121667,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 35.657211342770566, \"min\": 9.025198419806312}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004705777681288424,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0069302240541289205, \"min\": 0.0038300854734811193}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 656.7656875514036,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 27087.399088370676, \"min\": 296.25830824573484}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1586865514938697,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.983230917898558, \"min\": 0.1272268885723527}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.038264957360571,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 108.82013824566083, \"min\": 9.853270495405166}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.0048145171980548546,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007967374865143295, \"min\": 0.004189977415087033}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4102.834507193036,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8236.589433586827, \"min\": 705.2254672307673}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5136775425363499,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8077398221498968, \"min\": 0.2957229591557126}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.18387061993679,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 79.75371695346955, \"min\": 17.866306043515657}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.0076929638265370625,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008697539856658628, \"min\": 0.007153934692172364}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6909816ffe8b9b62b227478b3ad43387ac045111",
          "message": "Use the tag as a proxy for the alloc info when clearing shadow. (#281)",
          "timestamp": "2026-07-13T16:31:11-04:00",
          "tree_id": "f9a3991733efa8eb3e66dc578fbc07c3af0eef64",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/6909816ffe8b9b62b227478b3ad43387ac045111"
        },
        "date": 1783982966333,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 351.3796424984744,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1129.2151078212432, \"min\": 260.99021154829614}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.10580132794596252,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.22521236871356395, \"min\": 0.0940287959140854}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.100177586241957,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 10.721390242591552, \"min\": 6.273210115956091}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0021907965511845265,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002876931964739043, \"min\": 0.0019050825003558926}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 596.850217104398,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22819.9657198755, \"min\": 272.2985006594162}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1309829826882023,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.955139031877279, \"min\": 0.09765361340063096}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 6.865519995226418,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24.036815980070358, \"min\": 5.829127291748416}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002227014258939026,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0024669193880105383, \"min\": 0.002014604774982354}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3723.128534962923,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7634.917654963225, \"min\": 615.3494404971019}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.43256072741813056,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7220378605026111, \"min\": 0.22878437553659944}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.063635085773928,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.73689010500049, \"min\": 10.080116802890734}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003031964967262481,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004143806602652661, \"min\": 0.002062575503169824}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 364.4536674035486,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1259.9162751241688, \"min\": 289.0737376039129}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.1320733538818397,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.26564327247198855, \"min\": 0.11478335966112871}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.713623711515211,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 30.930663941154823, \"min\": 8.497211817380443}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0039057367855941712,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006427329790735181, \"min\": 0.0034171202678196758}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 658.966920476608,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 28100.081648925876, \"min\": 278.62017708366983}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.15473068440886162,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9948884694976614, \"min\": 0.12206691956309342}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 11.097201722352008,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 105.45113199744465, \"min\": 8.157380489972443}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004025748864829056,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007486214806967272, \"min\": 0.0036374577106518427}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4082.3189404353093,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8333.526490531081, \"min\": 672.2700977091724}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5183051006674453,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8200309045197468, \"min\": 0.29475088659464127}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 46.244137650063536,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 77.50739051022852, \"min\": 16.157922552877828}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.0072664382270056236,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.00756782576876985, \"min\": 0.0070251297742411675}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ac51bb03a6a946eda1544e18d46cf7f40e861b61",
          "message": "Relevant Line Reporting in Diagnostics (#231)\n\n* extend backtraces\n\n* fix =help indent\n\n* first attempt at improved diagnostics\n\n* fix deps\n\n* move zst back\n\n* keep error origin\n\n* short bt\n\n* stack trace msg\n\n* remove redundant pending error\n\n* up span count\n\n* indent note + condense error match\n\n* Lock the tree once.\n\n* Clippy.\n\n* New allocations should evict exposed provenance.\n\n* Ensure that allocations happen under the global exposed provenance lock.\n\n* fmt\n\n* restore pending ub\n\n* add plain cargo and rustup\n\n* separate library paths into arr\n\n* fmt\n\n* fmt\n\n---------\n\nCo-authored-by: Ian McCormack <icmccorm@cs.cmu.edu>",
          "timestamp": "2026-07-13T17:14:28-04:00",
          "tree_id": "e221561fc8604d57290929aed346bffb4e282041",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/ac51bb03a6a946eda1544e18d46cf7f40e861b61"
        },
        "date": 1783991190821,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 364.2498267687997,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1184.1249229007747, \"min\": 241.42695460171674}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.10927176016411819,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2338077759738183, \"min\": 0.09667932301145789}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.037145526830531,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.15733975174102, \"min\": 5.031042592373868}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0021553770776913278,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0025272589502772142, \"min\": 0.001911284171183121}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 589.5650362038182,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 21612.59769812169, \"min\": 290.93311293552523}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13296468832907704,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.8977995435481048, \"min\": 0.1039645134853103}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.051492705992149,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.156659539029523, \"min\": 6.19552579028348}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0022987926606990333,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.00293232901461105, \"min\": 0.0020333834237375556}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3710.0361331985578,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7308.0176617921215, \"min\": 680.6107361778289}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4354609505545521,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7219458369129199, \"min\": 0.23549409193691848}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.481966763895766,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.721193495417324, \"min\": 10.40684946158815}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0030490507931914975,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.0040004312093300165, \"min\": 0.002148595911250464}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 375.5712788354161,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1349.1391819043424, \"min\": 274.63911122587683}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.13063500226024521,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.26848041819053087, \"min\": 0.1157812971993082}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.989378065688525,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 34.5465002178381, \"min\": 8.182285910286215}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0038386182458078704,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0066202676115279645, \"min\": 0.0033365932469918837}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 646.386324899663,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 27087.5918522023, \"min\": 275.8175372811999}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.15217908029990093,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9605869506341804, \"min\": 0.11987165700394939}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 10.920328161938865,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 105.98656694015342, \"min\": 7.902781999230006}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.0038951795878714884,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007671257054491038, \"min\": 0.003522002973860059}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4048.6257295864375,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8109.646847748935, \"min\": 668.0639025902619}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.4975718256588655,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7867139544210501, \"min\": 0.28168384631160637}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 47.17410732159472,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 78.83295215183146, \"min\": 16.591396600264886}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007172541705278627,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.007647556631059453, \"min\": 0.006934769771759049}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "ac51bb03a6a946eda1544e18d46cf7f40e861b61",
          "message": "Relevant Line Reporting in Diagnostics (#231)\n\n* extend backtraces\n\n* fix =help indent\n\n* first attempt at improved diagnostics\n\n* fix deps\n\n* move zst back\n\n* keep error origin\n\n* short bt\n\n* stack trace msg\n\n* remove redundant pending error\n\n* up span count\n\n* indent note + condense error match\n\n* Lock the tree once.\n\n* Clippy.\n\n* New allocations should evict exposed provenance.\n\n* Ensure that allocations happen under the global exposed provenance lock.\n\n* fmt\n\n* restore pending ub\n\n* add plain cargo and rustup\n\n* separate library paths into arr\n\n* fmt\n\n* fmt\n\n---------\n\nCo-authored-by: Ian McCormack <icmccorm@cs.cmu.edu>",
          "timestamp": "2026-07-13T21:14:28Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/ac51bb03a6a946eda1544e18d46cf7f40e861b61"
        },
        "date": 1784001488571,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 358.08509305653547,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1178.625975082227, \"min\": 292.33703304354964}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.10634437850768483,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23011116562437525, \"min\": 0.09422822150440338}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.261570202792147,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.0842424847334, \"min\": 6.352898041077748}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022054199994113997,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002538567606391007, \"min\": 0.0018837913256094115}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 585.0138486177565,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 21835.87189172199, \"min\": 283.1594537761851}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13166447587763205,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9371392011124087, \"min\": 0.09824381056111268}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 6.88060011989594,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.596263827307236, \"min\": 5.986124220150974}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002255787643885713,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0025336357862349545, \"min\": 0.001949633749512194}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3682.659116918218,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7227.252384635262, \"min\": 664.7220815717428}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4366297916533832,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7126408359832583, \"min\": 0.23722420242210543}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 17.997961811716152,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.877033621227646, \"min\": 9.693464828951154}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.002960790764011196,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004191520465759018, \"min\": 0.002112605997620445}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 358.8950395753827,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1374.1141963507564, \"min\": 209.57027958522332}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.13914570164918932,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2872775905649672, \"min\": 0.12146106825302554}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 11.101082590370531,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.271473025006806, \"min\": 6.137939714447196}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0043154954908715655,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.007609933206383237, \"min\": 0.003755047595726705}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 616.783220372018,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 25736.56972320991, \"min\": 273.3121392278528}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.16058088255142472,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.8960876971517018, \"min\": 0.13017813392960095}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 11.32394777779761,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 128.93962430006718, \"min\": 8.38793914523324}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004412109980846576,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.009499355894746176, \"min\": 0.00402776353738527}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 3951.950701403712,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8150.826367347658, \"min\": 660.4430149902716}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5242970185394519,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8303205703823349, \"min\": 0.2981544832402528}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.53701687008195,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 82.59064972221887, \"min\": 17.279014564152266}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008017370213465621,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008421425931477588, \"min\": 0.0077952381686064495}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "24c23b07bd4f1834f896a1ecab8a7bec24b56b15",
          "message": "Merge pull request #286 from BorrowSanitizer/bench3\n\nexclude test_bit_vec_iterator in crates.json",
          "timestamp": "2026-07-15T17:05:55-04:00",
          "tree_id": "e6c889d8a64e558f1127f61074c025c739cd446d",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/24c23b07bd4f1834f896a1ecab8a7bec24b56b15"
        },
        "date": 1784159167077,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 585.336924530381,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22330.10092755984, \"min\": 264.8598468457233}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13196175319892503,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9226656658758239, \"min\": 0.09840367218575094}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.402232186621267,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.700996475070067, \"min\": 6.109243321340548}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002484822358031662,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0027511208677164552, \"min\": 0.0020407024723036386}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3704.372074390864,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7346.333111209166, \"min\": 638.0268728352237}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4341501892908124,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7178394739108551, \"min\": 0.23516319913488803}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.564727823319874,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.31440991209994, \"min\": 10.794292842496374}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031399547329420898,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004202034318031809, \"min\": 0.002134182227378453}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 591.0806649416687,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12762.973394834933, \"min\": 296.78759323436117}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.17983819849385616,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.1232308415104266, \"min\": 0.1282330142314373}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.905903879697319,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.804205672164084, \"min\": 5.446374353060119}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.00354476085234094,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004001941188327788, \"min\": 0.0018075048476730933}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 628.0461372792478,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 25796.567862749464, \"min\": 181.7534835708169}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.16640704701466563,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.922539080867994, \"min\": 0.12397043406187573}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.331667410522881,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 125.37323243882625, \"min\": 6.529807711278861}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005358635970077702,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.009343682475157775, \"min\": 0.004646543734839016}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 3994.307424687398,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7992.297979101011, \"min\": 667.1528912672935}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5267014056015584,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8173324680015056, \"min\": 0.3068923141396512}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 50.98590182266016,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 82.89619323675339, \"min\": 18.400974892257118}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008565067679402566,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.009689381380941695, \"min\": 0.00789538968497607}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 549.876729972384,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 9457.92237833254, \"min\": 293.7417365640894}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.21963778404872586,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.8504534204673858, \"min\": 0.16239917154391686}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.577093047182721,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 82.93318170274428, \"min\": 10.405283312366242}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007738427888695018,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008930327077195375, \"min\": 0.006055139782423573}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "24c23b07bd4f1834f896a1ecab8a7bec24b56b15",
          "message": "Merge pull request #286 from BorrowSanitizer/bench3\n\nexclude test_bit_vec_iterator in crates.json",
          "timestamp": "2026-07-15T21:05:55Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/24c23b07bd4f1834f896a1ecab8a7bec24b56b15"
        },
        "date": 1784176217645,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 590.1537952864771,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22228.12034939761, \"min\": 282.5426527291488}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13372199071643578,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9396381140244787, \"min\": 0.10424552816122569}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.216663859736764,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.14064535076131, \"min\": 6.09096179802855}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002407599766305389,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002844766457534859, \"min\": 0.002019265551919525}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3721.233402380843,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7352.722753762741, \"min\": 659.70246372083}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4371762577649722,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7196766227103657, \"min\": 0.23748858378356652}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.769363488703917,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.215549388596767, \"min\": 10.944801430504693}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031393458315146262,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004193258344142419, \"min\": 0.0021705619144165157}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 584.0511112409336,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12335.741238273155, \"min\": 288.24889724398884}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.17971841494786966,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.0879119693914852, \"min\": 0.12700147508916165}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.871168522700049,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.97642145079509, \"min\": 6.167009452393275}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0035222717391807223,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004045205231746071, \"min\": 0.0018370338543759125}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 660.7635566050742,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 27414.91126123527, \"min\": 291.7258006210017}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.16060789422236021,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.0203251866806116, \"min\": 0.12732972672358553}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.071695194109518,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 106.84700754362069, \"min\": 9.676765542391417}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004881565794204921,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007874025139270272, \"min\": 0.0041237169182223804}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4112.708915240634,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8478.73251077974, \"min\": 677.5221368404783}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5093516545716373,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8936779435276043, \"min\": 0.28412071441197384}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.12939312402832,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 78.80109130840027, \"min\": 17.456613294572165}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007602419399917638,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008490430764291313, \"min\": 0.006572007182866738}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 581.6080609857202,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 10480.514473761936, \"min\": 232.71542954854516}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.21202487718845434,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.8557820641456989, \"min\": 0.15497013056184483}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.585890635961759,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 91.3911621432898, \"min\": 8.986151620042643}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007186958259175186,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008279319311075062, \"min\": 0.005458679283070975}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "24c23b07bd4f1834f896a1ecab8a7bec24b56b15",
          "message": "Merge pull request #286 from BorrowSanitizer/bench3\n\nexclude test_bit_vec_iterator in crates.json",
          "timestamp": "2026-07-15T21:05:55Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/24c23b07bd4f1834f896a1ecab8a7bec24b56b15"
        },
        "date": 1784262537310,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 592.3310036462352,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22006.824209928312, \"min\": 252.70013438469599}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.134801066760104,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9304652329720369, \"min\": 0.10280442556920605}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.10548403535974,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.28885482228318, \"min\": 5.498474512826414}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0023595201946849716,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0032793105138719785, \"min\": 0.0020429265086721613}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3702.8901408569177,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7304.5827337419905, \"min\": 646.190302018272}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.43979107278365015,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7411866889521395, \"min\": 0.23732271600451257}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.410130575519187,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.46185382569123, \"min\": 10.483656331786579}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003106972820941561,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004109303890821883, \"min\": 0.002150749478925934}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 587.7658748315266,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12234.013686567127, \"min\": 295.1057605312083}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.18119332172426714,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.1160771081250762, \"min\": 0.12714395507036141}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.906343433887142,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.605563629862743, \"min\": 6.223500063851772}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0035056386415308195,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004545169059529062, \"min\": 0.0018629755163528242}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 625.3603607767378,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 25296.015606110257, \"min\": 282.59332782330733}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1662290695240197,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.899271829626368, \"min\": 0.12243560359517151}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.384040059269447,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 118.38115015753513, \"min\": 9.96821897541003}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005374466210240058,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.00888827660268623, \"min\": 0.0045878691904465705}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 3999.167850070429,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8062.943579395825, \"min\": 658.9195036502703}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.528520756948201,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8159734042950068, \"min\": 0.3066778492038896}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 50.78323549972452,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 82.26153096331305, \"min\": 18.2471107365708}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008519864217282569,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.009039656433771404, \"min\": 0.007886145516895805}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 529.3981374469973,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8652.751712864485, \"min\": 290.98494038624506}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.22168141694028548,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.8134501235616429, \"min\": 0.16401608194073944}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.48134125669837,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 82.261183750565, \"min\": 10.273206103501689}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007919511971607932,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.009081634269489179, \"min\": 0.006471595206042151}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "24c23b07bd4f1834f896a1ecab8a7bec24b56b15",
          "message": "Merge pull request #286 from BorrowSanitizer/bench3\n\nexclude test_bit_vec_iterator in crates.json",
          "timestamp": "2026-07-15T21:05:55Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/24c23b07bd4f1834f896a1ecab8a7bec24b56b15"
        },
        "date": 1784348730728,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 585.926044986088,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22315.662285209833, \"min\": 235.04058944491885}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1327454982764386,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.946488397507038, \"min\": 0.10191607268003658}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.0795989560677794,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.05255941348709, \"min\": 5.017199054472986}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0023768802051645677,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0026592931279338116, \"min\": 0.0020107644065277775}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3721.2140300252536,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7539.533065955852, \"min\": 640.9326865895093}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.43918332386892206,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7223909482473067, \"min\": 0.2367190277755775}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.41944134804193,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.130490300087562, \"min\": 10.511495698289488}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003112560297377887,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004013616187003125, \"min\": 0.002144157550121454}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 582.5779851769942,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12632.328571507696, \"min\": 277.67816986280417}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.17781608857647077,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.1000448073817854, \"min\": 0.12523858755836528}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.085818518152784,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.33694074448264, \"min\": 6.315620119753388}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0036622279001227065,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.0044148794078132025, \"min\": 0.0017844050705462483}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 677.8942799258385,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 28528.965733493067, \"min\": 300.1460484262542}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.15849194801668862,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.0070414795154874, \"min\": 0.1266783105280055}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.265090215434,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 112.14853223453592, \"min\": 10.061588684937297}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.00481667629430621,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.00788976222146185, \"min\": 0.004118189514675741}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4241.760179415578,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8661.003001702888, \"min\": 564.0435450590787}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5060919601292722,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.808483343738191, \"min\": 0.28576681274051097}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.37391604918061,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 78.88527037051486, \"min\": 15.365150910512657}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.0074410028981424375,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008119556894032775, \"min\": 0.006830758281367881}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 605.5371117962068,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 11516.29578970853, \"min\": 297.108698588359}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.21101159410569065,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.9335794816737669, \"min\": 0.15706753860819}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.686179292647212,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 82.29611164093494, \"min\": 9.54922219771941}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007085169287979251,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008069887408157552, \"min\": 0.006036070058593796}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "24c23b07bd4f1834f896a1ecab8a7bec24b56b15",
          "message": "Merge pull request #286 from BorrowSanitizer/bench3\n\nexclude test_bit_vec_iterator in crates.json",
          "timestamp": "2026-07-15T21:05:55Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/24c23b07bd4f1834f896a1ecab8a7bec24b56b15"
        },
        "date": 1784435499591,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 588.9563186810428,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22409.61770899956, \"min\": 241.7208000375678}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13092325713907554,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9034086217048738, \"min\": 0.10113326915913907}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.3040419291988865,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22.97112952705649, \"min\": 5.560944621413124}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002410007616124437,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.003097063798516089, \"min\": 0.00195110182421986}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3685.235210951464,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7384.072626774075, \"min\": 636.2965897868588}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.43818090708645024,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7255236366731331, \"min\": 0.23514751123084798}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.36681326580586,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.19878831101208, \"min\": 10.667241727817155}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003139683620712505,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.0041867935926926374, \"min\": 0.0021009436116753823}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 584.7514455390973,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12597.452149006273, \"min\": 289.6054977019585}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.17719634748706778,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.0873260866231336, \"min\": 0.1241792249389797}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.11651546052065,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.439344361516184, \"min\": 6.639982450430557}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.003643098365651921,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.0045575549525837785, \"min\": 0.001780079993218954}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 661.7750724089534,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 27720.301091359433, \"min\": 294.21194999448176}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.16013225551805557,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.020482530845315, \"min\": 0.12801666242376367}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 12.898515104716989,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 107.47809466540222, \"min\": 9.713650223397165}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004828206823198529,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007833883622125355, \"min\": 0.004160186189921062}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 3911.1060342323653,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8105.541071805626, \"min\": 691.047011576557}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5090879903903885,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8068599436329024, \"min\": 0.29245021974168667}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 46.956490310929134,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 79.07318299972029, \"min\": 18.064735148458364}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.00769990035480301,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008399685667023473, \"min\": 0.007124700168703192}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 579.8098757902533,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 10300.7061687946, \"min\": 292.3782491775016}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.21088146796695,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.8523672137134035, \"min\": 0.15556441315615796}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.835367083498038,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 92.73383661853717, \"min\": 10.550769005937125}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.0072964602415299075,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008261092363156069, \"min\": 0.00569944538442339}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "24c23b07bd4f1834f896a1ecab8a7bec24b56b15",
          "message": "Merge pull request #286 from BorrowSanitizer/bench3\n\nexclude test_bit_vec_iterator in crates.json",
          "timestamp": "2026-07-15T21:05:55Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/24c23b07bd4f1834f896a1ecab8a7bec24b56b15"
        },
        "date": 1784522583589,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 592.1271470515532,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22041.37385863548, \"min\": 296.11204534750954}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13384337824238057,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.965075574055641, \"min\": 0.10281540979527795}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.093434915265873,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24.521587854959755, \"min\": 6.01368298387911}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0023250654080286624,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0027419192822078927, \"min\": 0.002101074264338786}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3656.824955542586,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7298.723465460901, \"min\": 655.2252823560398}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.43632066248183543,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7250207591291546, \"min\": 0.23589770286057235}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.367506750262987,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.227249724979472, \"min\": 10.158807925988087}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031141538047603796,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.00422785508965492, \"min\": 0.0020785684273723383}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 586.4664070562286,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12356.336263097748, \"min\": 247.34093074238237}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.17944863020648066,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.0775407259613685, \"min\": 0.12676737253838632}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.9270128217043165,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.477148814154265, \"min\": 5.331831150783544}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.003531557407206378,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004921778909168537, \"min\": 0.0018189551546198212}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 743.8290798608612,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 32230.386887297478, \"min\": 297.867297713468}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.16946426934873512,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.4194030940331013, \"min\": 0.12485234118052885}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 9.875746818486409,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 35.31913267477642, \"min\": 7.846217889494197}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.003735519039447424,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.004504166061187108, \"min\": 0.002651262585544618}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4297.433452935674,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9040.086727106343, \"min\": 617.4861696315633}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5288024510876723,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8404151660354211, \"min\": 0.29601004345132237}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 23.335619872089303,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 35.03455972207605, \"min\": 11.326283520668573}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.004353782778082743,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.0059032655270437875, \"min\": 0.0030493839074357174}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 634.7868367716952,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 10859.298084208333, \"min\": 326.1028654778576}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.22103129955272904,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.85271456033262, \"min\": 0.15809400489684824}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 11.567993047842556,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 35.01969776461813, \"min\": 8.76832279165394}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.005741858195258267,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.006841052236002202, \"min\": 0.002558804347742838}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1bce21c7a3d62d35595012bf1353ed4c578d71df",
          "message": "Merge pull request #290 from BorrowSanitizer/hash_bench\n\nRevert hashbrown bench for continuity",
          "timestamp": "2026-07-20T12:42:58-04:00",
          "tree_id": "279913d4ffd43cf9c2625d5241da4cdba1ada7f5",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/1bce21c7a3d62d35595012bf1353ed4c578d71df"
        },
        "date": 1784575655299,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 363.9115764654049,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1166.2350408026368, \"min\": 276.436218235355}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11041717103111168,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23317729855627872, \"min\": 0.09774941036040835}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.396045216669673,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.233632831643476, \"min\": 6.312387818783813}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022950201228012935,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002989426121967006, \"min\": 0.0019618462737416324}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 588.4341516763822,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 21397.214628814072, \"min\": 267.59562677509643}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13561370430050634,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9525261940897627, \"min\": 0.10265350287158771}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.189269615562546,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.258425403355528, \"min\": 5.887998933257031}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.00237502395590231,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002736571297783795, \"min\": 0.002042938305161334}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3708.081817645202,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7295.815808690374, \"min\": 672.3338621213693}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.43983629209104935,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.718314358463322, \"min\": 0.24204544902956168}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.383983339162697,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.108232165654215, \"min\": 10.140180774924202}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0030350981992589643,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.00386995426871222, \"min\": 0.0021846012168821056}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 591.4003149782038,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12048.883378403805, \"min\": 298.1419437460263}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.18124929341525742,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.0588670742887143, \"min\": 0.12916266229502835}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.980596612954983,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.976312124906226, \"min\": 6.196851338072944}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0034781564144400635,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004124190393092422, \"min\": 0.0018410560398052014}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 384.56761548554874,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1352.1528245479071, \"min\": 283.664962209693}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.1344600631767989,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.27111489610698014, \"min\": 0.11619745424978145}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.111735216574253,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32.71656059042192, \"min\": 9.426026098030809}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0046607786412684905,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0067115038239392725, \"min\": 0.00399577148711078}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 673.008506694047,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 28303.65114830462, \"min\": 297.8977925932037}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.15876754845711874,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9924948075573148, \"min\": 0.12564588985912126}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.146778687512471,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 106.47394356246664, \"min\": 9.79253757757413}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.00483591532620028,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007495456277946424, \"min\": 0.004074382624656344}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4088.352500528239,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8418.962624009384, \"min\": 566.3951925634408}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5100575329436002,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8095401454403266, \"min\": 0.28484028290206825}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 46.351840958604015,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 76.1465206824903, \"min\": 13.782639984110752}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007357487530634203,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008242877152646608, \"min\": 0.0068300342939213695}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 609.4346205539371,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 11213.49973765377, \"min\": 303.6578414449241}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.21110919674383638,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.9033198681642228, \"min\": 0.15443795858348844}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 16.077906844893903,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 89.70120495284618, \"min\": 10.41597705448325}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007138681043286851,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008185220535707477, \"min\": 0.006040329238320993}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "1bce21c7a3d62d35595012bf1353ed4c578d71df",
          "message": "Merge pull request #290 from BorrowSanitizer/hash_bench\n\nRevert hashbrown bench for continuity",
          "timestamp": "2026-07-20T16:42:58Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/1bce21c7a3d62d35595012bf1353ed4c578d71df"
        },
        "date": 1784608238916,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 354.5459742802416,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1096.8661487127413, \"min\": 275.02893259648295}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.10847887627459503,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23092257481734546, \"min\": 0.09642763663734451}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.144876456243389,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 10.347588374897812, \"min\": 6.333591563253451}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022367466722806586,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0025848840343649458, \"min\": 0.0019450089144955904}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 591.7660261119762,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22386.356421276945, \"min\": 282.84159582030617}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13231541415956732,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.8525027675181045, \"min\": 0.10294011900575684}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.036110491529133,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.269897885120074, \"min\": 5.91231637395155}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0023354980717693215,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.00265073792728703, \"min\": 0.0019256170776892204}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3707.3241550399744,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7323.000269644387, \"min\": 625.4021959757195}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.43455350164144935,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7146444572395988, \"min\": 0.23556999091446337}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.57355418657867,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.907186455374745, \"min\": 10.688882531625076}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031941768066346054,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004854517251329776, \"min\": 0.0020711298887215726}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 585.997703970003,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12631.616643146393, \"min\": 244.67139036461023}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.17900318926040432,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.104667273714391, \"min\": 0.12485937266879525}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.84993014790463,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.675489875139778, \"min\": 5.685675185533682}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0035323292660181913,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.003967669903788491, \"min\": 0.001828510293242773}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 386.16498777533684,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1351.6191612556656, \"min\": 168.65026350966713}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.1357818266837148,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.27296014284188336, \"min\": 0.11965096029330734}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.146178532424834,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 34.53960283294675, \"min\": 5.982910211842151}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004688650364527699,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006724716457449941, \"min\": 0.003920893542727986}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 674.4765073808093,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 28257.891384897113, \"min\": 293.9768576294993}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1609811302350157,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.0913123916469094, \"min\": 0.1178300413330119}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.109308739203339,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 105.38280158272045, \"min\": 9.78610266193612}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004834418037033039,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0077991792032366895, \"min\": 0.00416367323868495}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4085.9963919579654,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8785.412374458198, \"min\": 692.4313439868745}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5097956072404088,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8677195161069433, \"min\": 0.28884913297396647}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.70035304384776,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 78.63130485188105, \"min\": 18.7968851541896}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.00780477634916229,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008515367752010993, \"min\": 0.0068332100609818465}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 576.199282368298,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 10068.582162026807, \"min\": 298.31335387677643}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.21322219150636973,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.8435018640885074, \"min\": 0.15579724843310064}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.590289399902293,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 86.38290115791371, \"min\": 9.296382746514654}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007258697774361381,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008035611976926905, \"min\": 0.0052983682209761206}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1af5041345aa35ac1250368814285e10c400820b",
          "message": "Intercept `clang` invocations instead of setting `CFLAGS` globally. (#289)\n\n* Ensure source reference counts are incremented before decrementing destination counts. (#283)\n\n* Remove trailing comma to fix benchmarks.\n\n* Require matching borrow tags for reference count operations on `LazyTree::Uninit`. (#284)\n\n* debug_assert -> assert\n\n* Only decrement or increment refcounts associated with the current tag.\n\n* Enable debug assertions within the runtime during UI testing. (#285)\n\n* debug_assert -> assert\n\n* Only decrement or increment refcounts associated with the current tag.\n\n* Enable debug assertions during UI tests.\n\n* Fixed assertions.\n\n* exclude test_bit_vec_iterator in crates.json\n\n* rm std\n\n* Intercept clang instead of setting CFLAGS globally.\n\n* Remove tmp ignore.\n\n* Force flate2 to build zlib statically.\n\n* Synced comments.\n\n* Update cargo-bsan/src/phases.rs\n\n* Update cargo-bsan/src/phases.rs\n\n---------\n\nCo-authored-by: Molly MacLaren <mojeanmac@gmail.com>",
          "timestamp": "2026-07-21T11:46:13-04:00",
          "tree_id": "d270e749402c4606bd5318a90b32384f09cc5f79",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/1af5041345aa35ac1250368814285e10c400820b"
        },
        "date": 1784658173851,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 365.8533284521028,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1186.2761290147303, \"min\": 293.35082864883947}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11115469824594354,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23484509263811681, \"min\": 0.09797138760505558}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.167928809327864,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.505135908096806, \"min\": 6.3226971869636674}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002226119210574717,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0029878630871519097, \"min\": 0.0018923798051452142}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 583.4867579380318,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 21416.002430357872, \"min\": 274.9275532994281}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13416053444197434,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.8873038809402405, \"min\": 0.10415920342737338}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.013635321638956,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.193530240251924, \"min\": 6.023414671026519}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002337347801019938,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0025139478606942545, \"min\": 0.0020439500685283034}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3712.7493441013526,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7407.913363232177, \"min\": 688.6733707601913}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.44534107745965196,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7214735391222875, \"min\": 0.24163787594414796}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.43840495106071,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.09951887747696, \"min\": 10.595769167876078}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031364266989467944,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004087145864708127, \"min\": 0.002195988683994636}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 591.8489304142474,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12633.124100596495, \"min\": 297.1773962297297}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.18033446305863374,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.1098557534732783, \"min\": 0.12784839251680352}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.228350624268263,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.547470842707398, \"min\": 6.848511792089673}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0036909441996671867,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004356818222117624, \"min\": 0.0018011785890351994}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 367.5759723087521,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1331.5801135685986, \"min\": 293.73897711171037}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14188875421826178,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2788004531794292, \"min\": 0.12549686943275104}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.429416029140151,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.47706198247471, \"min\": 10.579880875551547}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0052436748067077365,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0077542185000784155, \"min\": 0.004355982048781905}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 617.214261964463,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24904.26359170689, \"min\": 284.6406098241933}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1660611425023183,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.8941413873944895, \"min\": 0.13346346098207834}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.329039617106345,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 119.51940962785548, \"min\": 9.776973142891944}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005396269983050263,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.009090277234636367, \"min\": 0.0046678449168378626}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4023.615796301774,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8160.4251038372695, \"min\": 655.874261948946}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5285556769694155,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8222967066062714, \"min\": 0.3071928257058622}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 51.781794727189435,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 87.46667882641378, \"min\": 18.58792259652718}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.00866694547734159,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.009666917617712456, \"min\": 0.00802515971416214}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 543.6245453577291,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 9227.361702591103, \"min\": 292.1090465378714}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.22002587336025936,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.8507950957413739, \"min\": 0.1589109356481506}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.911716550508693,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 86.45057237896631, \"min\": 10.488793575485914}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007951746124110128,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.009489106405766504, \"min\": 0.005991559786840074}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "1af5041345aa35ac1250368814285e10c400820b",
          "message": "Intercept `clang` invocations instead of setting `CFLAGS` globally. (#289)\n\n* Ensure source reference counts are incremented before decrementing destination counts. (#283)\n\n* Remove trailing comma to fix benchmarks.\n\n* Require matching borrow tags for reference count operations on `LazyTree::Uninit`. (#284)\n\n* debug_assert -> assert\n\n* Only decrement or increment refcounts associated with the current tag.\n\n* Enable debug assertions within the runtime during UI testing. (#285)\n\n* debug_assert -> assert\n\n* Only decrement or increment refcounts associated with the current tag.\n\n* Enable debug assertions during UI tests.\n\n* Fixed assertions.\n\n* exclude test_bit_vec_iterator in crates.json\n\n* rm std\n\n* Intercept clang instead of setting CFLAGS globally.\n\n* Remove tmp ignore.\n\n* Force flate2 to build zlib statically.\n\n* Synced comments.\n\n* Update cargo-bsan/src/phases.rs\n\n* Update cargo-bsan/src/phases.rs\n\n---------\n\nCo-authored-by: Molly MacLaren <mojeanmac@gmail.com>",
          "timestamp": "2026-07-21T15:46:13Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/1af5041345aa35ac1250368814285e10c400820b"
        },
        "date": 1784694311114,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 360.0208363053489,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1172.2103855605744, \"min\": 279.11663582155467}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.1096189010487052,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.22293486478218025, \"min\": 0.0977452303097995}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.2727376484640995,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.53078267667917, \"min\": 6.163796183781105}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022598895036063747,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0027916544259506256, \"min\": 0.0020354707881086206}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 587.6050369004857,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 21516.18858596104, \"min\": 286.83862828692247}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13365578678853735,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.909916795794278, \"min\": 0.102536622363833}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.209595259668535,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.327811429533742, \"min\": 6.108520361051417}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0023687499090294393,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002746401702357306, \"min\": 0.0020707282184475313}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3730.246288045054,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7257.7883676327865, \"min\": 688.0586498874949}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4428734554477941,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7211806430836395, \"min\": 0.23876956623303905}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.776523652810514,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.27573694351522, \"min\": 10.704466590486424}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003143474438040886,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004264141988382759, \"min\": 0.002172427033539062}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 597.1083841288547,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12759.412821969296, \"min\": 291.36363779481275}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.1811981930368792,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.1064947149062379, \"min\": 0.12836536851459993}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.06343486229822,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.673009040384084, \"min\": 6.261116265466564}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0035841997328023476,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.00449778326814459, \"min\": 0.0018136676666087744}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 360.9245268588745,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1305.4772494674262, \"min\": 281.02102795006203}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14226025022284197,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2897601025599721, \"min\": 0.12617586130843736}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 12.979428926993528,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.81538617199477, \"min\": 10.151276453468181}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.00517978464229898,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.007721138150391465, \"min\": 0.004298641377035101}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 621.4077086767769,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 25564.85315449423, \"min\": 276.864996918765}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.16593963762304142,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9163521455905501, \"min\": 0.13514283016398773}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.058283727046149,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 119.91687610867645, \"min\": 9.686589816528176}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.0053146136531566895,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.008989019472735737, \"min\": 0.004516934881443195}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 3983.7963219882317,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7974.317360262282, \"min\": 658.6863865100537}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5265536354133392,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8198341831401422, \"min\": 0.30675810986808133}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 50.89823746266186,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 83.7579058476793, \"min\": 18.49157264121868}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008562688563134002,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.009364408057182048, \"min\": 0.00797397270968266}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 525.2715308460993,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8588.377472826194, \"min\": 284.1774200314861}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.21828259376476705,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.8093542864077989, \"min\": 0.1612274497680769}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.66187274186262,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 87.8060006125453, \"min\": 10.052984779354595}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007834542505909913,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.009228438558861997, \"min\": 0.006151326310295097}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "947d2acbcf4c9ddd25042c0740de0d4c129c4443",
          "message": "Assign invalid provenance to null pointer constants. (#291)",
          "timestamp": "2026-07-22T11:46:58-04:00",
          "tree_id": "3c0a6950c2f7dc8bcfcc5ad2e5d0aef477278465",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/947d2acbcf4c9ddd25042c0740de0d4c129c4443"
        },
        "date": 1784745209000,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 367.05307138426525,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1159.8974017258545, \"min\": 302.0582951544682}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11177168996399066,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23540119183479072, \"min\": 0.09978448535664089}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.211732768317306,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.42854292100923, \"min\": 6.057587259777967}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022444556059460804,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002966168161023944, \"min\": 0.0019586788739687842}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 600.3578771363044,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22350.25970484179, \"min\": 289.7090861922982}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.13579734578909916,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.9723355962023368, \"min\": 0.10343322394394802}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.072930225672423,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.738922182512262, \"min\": 6.02619663253779}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002327765682818386,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0032273040168870715, \"min\": 0.0020900141534677097}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3718.2128232702644,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7328.625184006265, \"min\": 657.6946107250109}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.44528149602565464,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7214232562975929, \"min\": 0.243951525922301}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.468215171250122,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.64037873500929, \"min\": 9.687022778980454}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0030707788283352963,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.003921656207814198, \"min\": 0.0022018368392572197}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 591.4023292693312,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12509.742371981218, \"min\": 270.22324772916454}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.1790049944696463,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 1.0874478716813147, \"min\": 0.12747814747373848}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.132157395454032,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.46406683381006, \"min\": 6.550722568449144}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0035946451684703467,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004846448656232524, \"min\": 0.0018504217734254477}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 378.7780144711724,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1365.3796708644145, \"min\": 302.13283442491866}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.13890892601105925,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.28513720716572405, \"min\": 0.12089692891365099}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.637750642636712,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.4736560217461, \"min\": 10.629104711903167}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.005059991326681081,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.007581148837924655, \"min\": 0.004178953523789776}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 625.4563596951151,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 25085.05467859328, \"min\": 194.5145577642225}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1640486684656555,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 1.8460122684421734, \"min\": 0.12913605498498598}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.440372534513923,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 115.18663092091059, \"min\": 7.113088242515768}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005314410484250496,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.008517075574441275, \"min\": 0.00451993231886985}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4084.4516825516685,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8480.08673588908, \"min\": 667.9854422891542}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.529826966936009,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8580437358917368, \"min\": 0.29940703622148496}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 50.48374646314883,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 81.50539469510156, \"min\": 18.888204805435425}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008295578821320496,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.009182052095545788, \"min\": 0.007780407913163832}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 557.22669278167,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 10052.724591283157, \"min\": 282.1910944787761}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.21849025643660186,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.8989388361833567, \"min\": 0.15385147542929736}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.708015306035518,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 84.30188285866527, \"min\": 10.268977675223272}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007780043012180932,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.009136250538914259, \"min\": 0.006634907783458787}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "56b076f25b6d21d3734ec8acf8a8dc3c945f2856",
          "message": "Merge pull request #288 from BorrowSanitizer/vnt1c/better-pruning\n\nMulti-Child Compaction & GC Minimum Tree Size",
          "timestamp": "2026-07-22T12:20:36-04:00",
          "tree_id": "444a5ae897c3c407d606657da64a38cd6c445802",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/56b076f25b6d21d3734ec8acf8a8dc3c945f2856"
        },
        "date": 1784757073711,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 376.1277392625707,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1226.5640123424273, \"min\": 291.54206975517076}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.1143121550272295,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.24108672177582066, \"min\": 0.09829100367761096}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.570868869963643,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.33360425993214, \"min\": 6.203526388926218}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0023565044705463846,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003123067276124337, \"min\": 0.0018708000859296466}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 719.1748264401479,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 31478.94721337575, \"min\": 302.46499626118066}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.14894624184810887,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.8066102131566817, \"min\": 0.10172940026291737}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.210542777172161,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.211499933897596, \"min\": 6.086381008278337}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0023710725589141347,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.003284589141271382, \"min\": 0.0019359099875244686}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3932.0990860278866,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7619.127475115214, \"min\": 713.4894764257739}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4660602261973467,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7533420649091862, \"min\": 0.25451272736550684}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.546783210544472,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.871571168774587, \"min\": 10.545297030208127}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031120916074897347,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004047459053743757, \"min\": 0.002151024121152154}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3235.392271397069,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 164773.73583754175, \"min\": 313.8242950577}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.41841011523917926,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.45546119806959, \"min\": 0.13228098973192579}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.929244592903066,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 24.01878937468939, \"min\": 6.281006272017279}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.003484845660357336,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.0040113652367194, \"min\": 0.0018861866766462976}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 385.7339122313886,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1386.0174856881642, \"min\": 257.4137060232836}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.15180168630188864,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.29841593430530866, \"min\": 0.13499173425214014}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.040258428004467,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 39.62927659461024, \"min\": 8.87913785726225}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.005185746808439139,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.008191337998869057, \"min\": 0.004245158500325423}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 741.1258771137138,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 33850.10079361628, \"min\": 302.25858109814635}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.18379270832938588,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.536219991097825, \"min\": 0.1448820514804718}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.185042358229317,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 118.19005376263416, \"min\": 9.760477443093626}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005409449533562703,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.008855393930119401, \"min\": 0.004763475372693869}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4204.110905516346,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8398.547698857357, \"min\": 700.1598849033012}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5589043916519315,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8673281751871131, \"min\": 0.3250223459878037}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 50.76119797985088,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 85.06139034624826, \"min\": 18.275983086335117}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008531910526282247,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.009367572396723192, \"min\": 0.007841069535978065}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 1930.2228858290566,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 88893.7019806471, \"min\": 259.66578920911525}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.36225602368097076,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.428751169968667, \"min\": 0.17160670544994028}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.750454717770229,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 93.18151184269246, \"min\": 9.844807784373803}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007963491358514877,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.010216281554084097, \"min\": 0.005859593886588792}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "56b076f25b6d21d3734ec8acf8a8dc3c945f2856",
          "message": "Merge pull request #288 from BorrowSanitizer/vnt1c/better-pruning\n\nMulti-Child Compaction & GC Minimum Tree Size",
          "timestamp": "2026-07-22T16:20:36Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/56b076f25b6d21d3734ec8acf8a8dc3c945f2856"
        },
        "date": 1784783996165,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 374.9399006124734,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1231.7789606507965, \"min\": 250.805080860231}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11411602023749826,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.24130082790597387, \"min\": 0.09865982830735424}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.519442465480279,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.364212129236213, \"min\": 5.634737681622851}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0023430926663443714,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003054406215478849, \"min\": 0.0018835998872623948}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 710.2055051668917,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 31249.596908731, \"min\": 295.4649540241767}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1463481901354883,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.758161289640726, \"min\": 0.10500248216511328}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.472819024463714,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22.677960738102705, \"min\": 6.35236125742116}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0024675919093564936,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002789659345044633, \"min\": 0.002001608968541641}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3944.9873218748844,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8417.807723037859, \"min\": 629.8571361595539}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4650153775191577,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.823430449509135, \"min\": 0.24254081542161818}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.477228210971493,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.464660991634478, \"min\": 10.881252512061522}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031691478763393763,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004323004181082259, \"min\": 0.0021467385528467615}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3164.2427851729785,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 160844.42042645585, \"min\": 303.7490843872795}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.41489280697694114,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.356817440372827, \"min\": 0.13107725580133936}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.299972384926035,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.55305482857503, \"min\": 6.580906309107655}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0036873046303597576,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004571274912261697, \"min\": 0.0018402568957263852}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 402.1760914674713,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1326.3616514018236, \"min\": 326.0979716493704}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14656037493464655,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2889360591399645, \"min\": 0.1281883577561561}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 12.926864121987977,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 31.662077408508516, \"min\": 10.313457549354439}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004774633378887657,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006765458582215821, \"min\": 0.004012781972256548}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 786.957625028141,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 36350.67771918626, \"min\": 301.57584630418535}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.17857318901311936,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.6705873323610705, \"min\": 0.13678141426439916}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 12.968319419943516,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 106.83076092112326, \"min\": 9.501883246406607}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004896105721665265,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007848571050763689, \"min\": 0.00411371479198615}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4369.748426739046,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9315.193866081345, \"min\": 711.3297961496993}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5362543406184104,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8472077104865203, \"min\": 0.3108449487799618}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.030148036151985,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 75.84819903171643, \"min\": 18.239781003357983}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007615452641411681,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.00877229822518127, \"min\": 0.006574773089712126}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2255.733748267817,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 105391.5511600193, \"min\": 327.26837228759103}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.35907089550052484,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.672969149354904, \"min\": 0.1677434149390673}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 16.056198131872744,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 87.17277579392093, \"min\": 9.997191119354973}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007292146006731892,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.00815201587636963, \"min\": 0.005695281003271713}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3719c654796c045623a6b79601042ffe4a628a3f",
          "message": "Merge pull request #295 from BorrowSanitizer/gc-opts\n\nGC nits",
          "timestamp": "2026-07-23T15:41:18-04:00",
          "tree_id": "f0c3f1099fa50ae65890d86aa34913561aba6e6f",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/3719c654796c045623a6b79601042ffe4a628a3f"
        },
        "date": 1784848423957,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 361.75540962815813,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1229.5003348953499, \"min\": 273.6323671636652}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11009186327491996,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.24813321182314974, \"min\": 0.09592759866618533}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.91051078746858,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.69518185625223, \"min\": 6.679449871455098}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0024729665267174544,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0028958794975468085, \"min\": 0.0019318883644634007}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 723.7414504111066,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 32985.867983948316, \"min\": 275.56577281250105}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.14470856752173486,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.750052887320576, \"min\": 0.10216434128973204}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.538402827275339,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.66323689841622, \"min\": 5.986243597143184}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002505078248745622,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0028646064543313213, \"min\": 0.0019728191778220715}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 4007.6399245487846,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8156.7850723985775, \"min\": 664.0106488549037}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4650710277554643,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7754713115915239, \"min\": 0.24344319480587265}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.388546509397116,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.819799715184782, \"min\": 10.740222989215612}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003175353847486637,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004331930586703607, \"min\": 0.0020587189390814413}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3333.8205458558136,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 171172.87347546502, \"min\": 301.8760931302827}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.42899285651950314,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 15.301169032188932, \"min\": 0.1319234175873224}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.128097224367943,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.559909381111467, \"min\": 6.139631853187363}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.003654032236531809,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004196078691335566, \"min\": 0.0018314733063529791}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 405.8859982175452,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1413.6313990333144, \"min\": 330.5421799221741}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14307569428518807,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.279973929239211, \"min\": 0.12395053570121974}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.119832338787564,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 35.746831814070575, \"min\": 10.434685274608839}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004682429637322624,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006719969081097405, \"min\": 0.003939907409507561}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 764.9275760198572,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 34593.70288788018, \"min\": 307.14146749858713}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.17193676024726143,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.552990240141496, \"min\": 0.1253967333099118}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 12.917848271604536,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 105.6421429920425, \"min\": 9.850313096339974}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004728666359972026,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007796313707163356, \"min\": 0.004027514463829859}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4339.388403551201,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9135.15915577501, \"min\": 556.8072915835972}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5329443603506647,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8886100851082044, \"min\": 0.29315189877090353}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.04603262466697,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 77.79012246146843, \"min\": 13.899710372963979}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.0075287950121966365,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008495494420798045, \"min\": 0.006357969007628369}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2178.8524047006713,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 101576.2716646639, \"min\": 307.0419187135336}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.35508220388138856,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.438927424639587, \"min\": 0.1662704170995061}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.69962405124945,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 89.86331227827993, \"min\": 9.880190657013907}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.0072467858154914916,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008239452430932034, \"min\": 0.005452244931577869}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "3719c654796c045623a6b79601042ffe4a628a3f",
          "message": "Merge pull request #295 from BorrowSanitizer/gc-opts\n\nGC nits",
          "timestamp": "2026-07-23T19:41:18Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/3719c654796c045623a6b79601042ffe4a628a3f"
        },
        "date": 1784870185290,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 373.6652716461127,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1205.797583861769, \"min\": 299.1978557953494}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11313038582928292,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23378967886117205, \"min\": 0.09975335368289934}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.21330894566968,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.204355701511675, \"min\": 6.162473906796897}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002232986517270212,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0030535128704341627, \"min\": 0.001953478999647682}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 720.3064294632479,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 32233.401284931995, \"min\": 293.30516097810926}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1478604337431144,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.918244145932251, \"min\": 0.10228766359310383}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.059171132447253,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22.931331732026496, \"min\": 5.749386982712627}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0023296477345776624,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.003063976110427335, \"min\": 0.002055718241119255}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3945.3628547177937,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7873.039204558094, \"min\": 669.7913045309966}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4632555252555053,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7632489523239485, \"min\": 0.24832814939017683}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.62581285622154,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.569371622929815, \"min\": 10.203578704376005}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003116444360744785,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004384562650883115, \"min\": 0.0021445461825266897}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3382.0380411972524,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 173645.4408316576, \"min\": 303.14057007498235}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.42366292285342466,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.889858678875347, \"min\": 0.13383471812560255}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.931231782663138,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.499092041858972, \"min\": 6.181584455866338}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.003506540759024547,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004081720659243615, \"min\": 0.001842985250849812}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 391.9223984897732,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1394.6003500660445, \"min\": 207.56104403261773}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14339446833614408,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2977070030494086, \"min\": 0.12047541360589131}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 12.665042713182663,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 33.200578644403684, \"min\": 6.361420727523497}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004697123843724027,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0064939986577396015, \"min\": 0.003740970378079409}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 734.095278351945,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 33187.906691367956, \"min\": 225.55741171685702}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1706706549999943,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.367838794283532, \"min\": 0.12312381674478023}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 12.499001116784765,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 103.66160483407732, \"min\": 7.790067702767775}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.0047907729365865345,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007395885847408966, \"min\": 0.0038338544479673722}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4241.06801356885,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8677.381561438293, \"min\": 739.2859097265064}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5455559979131535,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8573574426568584, \"min\": 0.30852093781140116}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 47.64522225725273,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 77.92959981721735, \"min\": 18.303104059202415}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007772280746664721,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008757322528983251, \"min\": 0.007111610377946551}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2150.3917668720396,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 100288.86004594686, \"min\": 301.3715443995568}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.3534315335923359,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.398083176550845, \"min\": 0.16507516239778325}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.608433499840096,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 86.93136507090703, \"min\": 9.546515370668406}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007289130444347263,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008155699024806447, \"min\": 0.006113949371983508}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "3719c654796c045623a6b79601042ffe4a628a3f",
          "message": "Merge pull request #295 from BorrowSanitizer/gc-opts\n\nGC nits",
          "timestamp": "2026-07-23T19:41:18Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/3719c654796c045623a6b79601042ffe4a628a3f"
        },
        "date": 1784956153168,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 377.86281235634755,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1235.6927887001302, \"min\": 271.6938008010034}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11485159447129488,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23791203493836358, \"min\": 0.09867498119133276}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.172750608554846,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.61899922931255, \"min\": 5.535854905240713}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022318622559694065,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002895469776254591, \"min\": 0.0018828177741473458}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 715.0481209891589,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 31194.14465663587, \"min\": 302.05878500704813}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.14913972280229162,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.8107170177798757, \"min\": 0.10512440461505142}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.08559283890852,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.114123900882337, \"min\": 6.1309710572632765}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0023391049877704083,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.003002684311267884, \"min\": 0.0020826748774296715}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3911.4759458759436,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7639.55531261959, \"min\": 691.8435022058504}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4649494213513776,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7662935839032822, \"min\": 0.2466937948582164}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.4520919780221,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.87604899309514, \"min\": 10.480941099495263}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0030929196540753177,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004097888019624198, \"min\": 0.002202681034579188}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3183.507927543359,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 161787.01599229168, \"min\": 312.75617877205246}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.4122808975612239,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.092931924735296, \"min\": 0.13358662421367304}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.018431961911919,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.309182341691205, \"min\": 6.046544353549622}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0035409825602404944,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.003911945628854256, \"min\": 0.0018499508525534395}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 429.29201987986437,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1473.570471446887, \"min\": 229.5701848870732}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14343040753006278,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2972326317425115, \"min\": 0.12651236347993244}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.523796297683578,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 17.33416273306293, \"min\": 5.869449729157734}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0036334544558143,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0046362430335503855, \"min\": 0.0030536880968555762}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 868.9238164187154,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 41425.983983579696, \"min\": 303.6573482947586}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.18110180228940503,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 3.32393361161515, \"min\": 0.13112365956523592}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 10.23943135743422,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 33.793519362577015, \"min\": 7.670865988349683}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.0037413453830046797,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.004411487758651697, \"min\": 0.0027115207428400766}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4527.299271302703,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9269.7307598638, \"min\": 736.906524783187}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.547059388743774,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.865057081900648, \"min\": 0.30619898451869726}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 24.583796483651113,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 37.012257668835424, \"min\": 12.56374809021388}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.004441533175538271,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.0061629316475454955, \"min\": 0.003022832348525516}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 3524.807272885886,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 177277.4315218108, \"min\": 332.8765399275319}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.44344167674380613,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 13.418421639050132, \"min\": 0.1641418640688478}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 11.78481541184995,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 34.515314954977505, \"min\": 9.227672593884165}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.005748544365780132,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.006769562526404165, \"min\": 0.002551907666796369}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "3719c654796c045623a6b79601042ffe4a628a3f",
          "message": "Merge pull request #295 from BorrowSanitizer/gc-opts\n\nGC nits",
          "timestamp": "2026-07-23T19:41:18Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/3719c654796c045623a6b79601042ffe4a628a3f"
        },
        "date": 1785042997496,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 376.66488412737283,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1211.537028068575, \"min\": 309.2251981660472}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.1135524853508027,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23874689754407377, \"min\": 0.09872289832373217}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.440626949447508,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.360621322925889, \"min\": 6.329472389860986}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002294489243943281,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002691905197218468, \"min\": 0.0019132160361881188}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 714.4032652636503,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 31506.234741623994, \"min\": 295.4072343149606}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.14641635447896287,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.8128745713548997, \"min\": 0.1018858788659096}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.519133784988113,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.47707254023517, \"min\": 6.163257442746872}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002460568266734883,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0036978790139298476, \"min\": 0.0020960314966179277}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3936.1822251767085,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7857.420727806031, \"min\": 674.4353531471338}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.46157322500113396,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7784679336190093, \"min\": 0.24413773311871553}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.34246636647732,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.71331318638258, \"min\": 9.379078839507496}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0030898746330089238,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.0041941551513979295, \"min\": 0.002144302117103029}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3184.609776774416,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 162070.40806752918, \"min\": 301.39801156535043}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.413217166610562,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.232419295702936, \"min\": 0.13336591530099717}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.213927891984591,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.90370052817976, \"min\": 6.450209444700464}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.00364619503898636,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.0041590098494616815, \"min\": 0.0018297600640705478}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 411.2687970623032,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1411.5023165796727, \"min\": 328.5381662080177}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.142776664373001,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.28060605831790136, \"min\": 0.12600284897186873}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.16287206845205,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 33.9610048151691, \"min\": 10.745070155590627}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004637589916099891,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006751433267776692, \"min\": 0.003943286789882389}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 764.7520206612961,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 34568.64738304902, \"min\": 310.03687668273494}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.17020094415945763,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.508845175647619, \"min\": 0.12756220694274895}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.02664301769276,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 105.1973348163647, \"min\": 9.778278201261266}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004729926408144988,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007634774453872348, \"min\": 0.0040813096717954985}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4373.997654173926,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8712.045182830687, \"min\": 740.4305101415171}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5355336619867708,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8312313292087824, \"min\": 0.3058264560145743}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.87937209977708,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 79.12661674441513, \"min\": 18.637667714630965}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007650674721937245,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008470134744556577, \"min\": 0.006989677018607042}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2283.7290015194762,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 107350.53217257303, \"min\": 318.9693995919504}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.3541038532443637,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.552127626000805, \"min\": 0.16271900720827712}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 16.0987509437909,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 90.64496686781614, \"min\": 10.151981890715833}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.0072970658635062415,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.00813227038104514, \"min\": 0.006099841838284624}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "3719c654796c045623a6b79601042ffe4a628a3f",
          "message": "Merge pull request #295 from BorrowSanitizer/gc-opts\n\nGC nits",
          "timestamp": "2026-07-23T19:41:18Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/3719c654796c045623a6b79601042ffe4a628a3f"
        },
        "date": 1785129426371,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 381.4031265649391,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1246.7858285883303, \"min\": 311.9119694763332}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.1159873871039654,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23924661901880775, \"min\": 0.10203690083129335}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 6.867694982092225,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.290153221966271, \"min\": 6.149353192331618}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0021352324149322196,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002456413335931546, \"min\": 0.0018954004500975961}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 720.8083102867927,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 31527.411376878168, \"min\": 305.0740189104816}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1501392626875914,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.814464198349456, \"min\": 0.10944579891384966}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 6.818075009693361,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.48675884867463, \"min\": 5.8936869750510645}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0022552499029491364,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0024925344686651135, \"min\": 0.0020870303237002143}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3862.9336631267083,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7459.5158081739155, \"min\": 722.4743633004991}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.46146040077058165,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7470939773462587, \"min\": 0.24895096663216676}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.18910176452765,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.92451659699119, \"min\": 9.660632712729461}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0029630740418488425,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.003623191165699599, \"min\": 0.0021777377468421306}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3225.6688523876255,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 163975.42845626242, \"min\": 318.31940064867143}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.42053946042672674,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.568590287840877, \"min\": 0.13375021115860689}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.8276039952925265,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.73935046032396, \"min\": 6.5271024879341395}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.003408276741738836,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.003761204529537766, \"min\": 0.001872832977175574}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 390.87022249846905,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1322.3976207454723, \"min\": 319.3725777871758}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.1493944413337949,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.28445935036336056, \"min\": 0.13313182529676762}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.663750299869236,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.67283652129065, \"min\": 10.641421320370032}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.005279630232810659,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.007830935663109204, \"min\": 0.0043476884021584955}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 743.1709978011069,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 33880.50697490978, \"min\": 300.78682808580385}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1766904893771196,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.44604390081117, \"min\": 0.13924593893727727}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.725169991124453,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 120.90297150883555, \"min\": 10.138850426116832}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005389926353651802,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.008728735265624558, \"min\": 0.0046858159956331595}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4352.721672991929,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8718.103786547746, \"min\": 696.1241495387051}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5597838588181222,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8684370855221744, \"min\": 0.3196866919111445}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 50.372417773429895,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 82.3400101045017, \"min\": 18.29699314983279}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008314220245845128,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.00923577385720001, \"min\": 0.0077805850421960735}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2020.6683309963164,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 93436.73222152308, \"min\": 312.40005595851227}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.36317120399052394,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.503026203287153, \"min\": 0.17148840391626194}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 16.269018174413187,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 86.69079059953435, \"min\": 10.955021317537044}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.008100946031086107,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.009350615990648167, \"min\": 0.006428433076440602}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "dd3336fa727ccf0d7c1ccf88d328257428be3c2a",
          "message": "Add `libunwind-dev` to Dockerfile dependencies",
          "timestamp": "2026-07-27T13:57:54-04:00",
          "tree_id": "e27e55aa39c3a0886762c4625b81782f054523fa",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/dd3336fa727ccf0d7c1ccf88d328257428be3c2a"
        },
        "date": 1785187550795,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 366.2488437347538,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1193.6914096007633, \"min\": 298.0814178553719}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11204270549518455,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.24546222780093177, \"min\": 0.09876306084688521}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.29343558713625,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.49693676673627, \"min\": 6.065966056185668}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022817667010774194,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002886390414137883, \"min\": 0.0019395600271309608}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 719.4758834703222,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 32612.475842599044, \"min\": 263.2150393123374}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.14681489059406294,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.867846731823954, \"min\": 0.10593581285152623}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.171253918859043,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.773971323291, \"min\": 5.715949616249835}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002395961312093358,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002741906408978618, \"min\": 0.0020906142266242274}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3929.46807847403,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7736.816862019644, \"min\": 682.1599005347344}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.46289417916674336,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7559719684331437, \"min\": 0.24666793567026823}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.24511770784707,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.604152999429907, \"min\": 10.293835160778896}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003104960492645519,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004073483844553626, \"min\": 0.0021482623898158018}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3404.0961920788077,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 175314.54711659916, \"min\": 295.11089835223765}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.42284582674797316,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.901410107243668, \"min\": 0.1289290547356167}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.027032922965372,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.326546411976473, \"min\": 6.422524530393893}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0036210886082887125,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004928093209869716, \"min\": 0.0017912981894318955}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 442.1419905638252,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1517.654217894824, \"min\": 333.9379322275981}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14247636190355714,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.29726441717120433, \"min\": 0.1250376337812723}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 11.071947104694333,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 18.09980655038387, \"min\": 9.375457633039366}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0036905339468312997,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.004609626108691136, \"min\": 0.0028416681095605454}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 951.8915053552474,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 47283.340794625954, \"min\": 326.776461986587}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.17961116196611973,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 3.1539437795962013, \"min\": 0.13055558091351052}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 11.001719009290314,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 39.48075128533024, \"min\": 8.906903808190576}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.0038706465161578016,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.005243931238664864, \"min\": 0.0026334871402382914}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4609.734356127572,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9438.420294214759, \"min\": 731.657594978975}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5453788577517822,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8647827450380126, \"min\": 0.2988724883788785}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 24.870983365239674,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 36.056586266436774, \"min\": 14.04453206806658}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.004620774342261868,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.00716059369040607, \"min\": 0.0029969223344203304}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 3286.4379649307198,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 163171.26284566848, \"min\": 334.5725159144635}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.42835073937075646,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 12.570177823306025, \"min\": 0.16396743544013492}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 12.045395602360697,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 35.498088864072045, \"min\": 9.272035529848031}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.005788957391423269,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.0068052523967976645, \"min\": 0.0025734116041433277}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "dd3336fa727ccf0d7c1ccf88d328257428be3c2a",
          "message": "Add `libunwind-dev` to Dockerfile dependencies",
          "timestamp": "2026-07-27T17:57:54Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/dd3336fa727ccf0d7c1ccf88d328257428be3c2a"
        },
        "date": 1785215799385,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 369.2947469826605,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1139.1561337069595, \"min\": 288.3873822180918}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11292168612834214,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23782664426209404, \"min\": 0.09383679418921385}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.303617318217548,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.007930098512196, \"min\": 5.925564631850878}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002290293461800368,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0029158995013316763, \"min\": 0.0018815002697673113}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 704.7474200812248,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 31979.93721315802, \"min\": 230.34754034576233}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1426739673581737,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.682087881110616, \"min\": 0.09883363785496622}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.406122127366887,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.763650626061995, \"min\": 5.105698781140175}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002489600732178333,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.003015243184242437, \"min\": 0.0019930057689069997}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3913.166496843714,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8075.584379164867, \"min\": 558.0642716298881}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4634728683124618,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.76832526073747, \"min\": 0.23499051581273314}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.51026831641089,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 27.798038063768306, \"min\": 8.935154703379592}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.00316772173531195,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.0043374140888847714, \"min\": 0.002082432229716297}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3360.0664938253367,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 173102.66105776787, \"min\": 281.7239251332459}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.4105270182968473,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.322612816088546, \"min\": 0.129825769818042}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.479091098950752,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.469650048223368, \"min\": 6.493401044115731}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0038628560343794013,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004467303079884205, \"min\": 0.0016980119733758302}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 406.41307794086873,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1342.358138065093, \"min\": 296.9525057294265}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.13883135752129383,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.27822418042469954, \"min\": 0.12188914126666885}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 12.874483511048753,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 31.90757451944276, \"min\": 9.579992124634018}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0044540629550687185,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006176092448751341, \"min\": 0.003728533791672515}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 767.2615848964692,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 34824.595744730555, \"min\": 277.0324273718977}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1650891326412071,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.3411132833444115, \"min\": 0.12800346842901622}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 12.96002132415923,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 104.07350819539877, \"min\": 9.843047472844416}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004607533243082497,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0069964307487293325, \"min\": 0.0040395922726624315}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4468.269341462858,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9082.059921457574, \"min\": 620.815837438569}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5247146651492827,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8116924819406148, \"min\": 0.3021874743814437}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 47.059409071944295,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 76.7906503725734, \"min\": 15.795129450402218}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007227126840287421,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008118757947896103, \"min\": 0.0065564707954967215}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2331.5425833135846,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 109924.59819793078, \"min\": 290.7174863447771}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.3557471360902303,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.82057499420045, \"min\": 0.16164211032840659}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.562286530304318,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 84.75692706772925, \"min\": 8.765548394774902}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.006937739711968108,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.007833687345607222, \"min\": 0.005484511851678853}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Gitter499",
            "username": "Gitter499",
            "email": "rafayel.amirkhanyan@gmail.com"
          },
          "committer": {
            "name": "Gitter499",
            "username": "Gitter499",
            "email": "rafayel.amirkhanyan@gmail.com"
          },
          "id": "9729f049fb9916fd09662181a09ce934c837b629",
          "message": "Benchmark stack-disabled mode via --no-stack flag",
          "timestamp": "2026-07-28T01:38:51Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/9729f049fb9916fd09662181a09ce934c837b629"
        },
        "date": 1785215947678,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 366.05567329095635,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1220.3386286187897, \"min\": 234.86643363189808}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11300467181746696,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23793165829536972, \"min\": 0.1003934330430471}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.406051373721379,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.229814942769233, \"min\": 5.383925748491511}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002338755888911885,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0027482930069562205, \"min\": 0.0019841935021392737}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 723.5131126032595,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 32669.94410907675, \"min\": 293.14824172111446}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1470586642661992,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.7802616217064107, \"min\": 0.1045971234615417}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.150805960547676,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.090247281107608, \"min\": 6.008918308891117}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0023871780145221116,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0031324808530887663, \"min\": 0.0019650149426958564}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3964.168664399768,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7758.630205512998, \"min\": 701.7428910491685}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4635366527801398,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7576565055757847, \"min\": 0.2474113872231419}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.600710820241016,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.598497058693916, \"min\": 11.446726883201928}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031934592190703505,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.0042367998073935135, \"min\": 0.0021185380294002484}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3231.7415411985635,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 165197.05084923547, \"min\": 285.2856301523501}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.41776542951054,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.600586160547312, \"min\": 0.13232927612543713}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.168233548833264,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.170309290853332, \"min\": 6.601689242718699}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0036648262891302184,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004156201654168283, \"min\": 0.0018711607983969074}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 405.1061257447295,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1416.7095183684844, \"min\": 321.2916638922597}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.1416714313788962,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2879561122866362, \"min\": 0.12207227585887385}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 12.954495017147348,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 33.9402894367529, \"min\": 10.40296966429071}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004595392651875676,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006703711001132137, \"min\": 0.003870675276620847}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 760.7733189210733,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 34578.431497754325, \"min\": 311.6089560441691}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.17125503645163223,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.547674814811028, \"min\": 0.12893647215159626}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 12.989899758229976,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 111.2936000229394, \"min\": 9.665469140801525}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004762991452734392,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.008199906402536192, \"min\": 0.004008053134861107}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4215.856627573885,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8585.168081009775, \"min\": 720.8381083359421}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5351111092024298,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8573660294232157, \"min\": 0.3078645459549232}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.012276779244516,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 79.24679787484428, \"min\": 17.730137257729616}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007711468904894008,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008310074009413438, \"min\": 0.007174336566291847}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2253.3841884220647,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 106038.5898732904, \"min\": 317.98649078453644}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.3561320529208982,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.67300788356014, \"min\": 0.16323933129649823}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.839171197490295,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 90.54220073187507, \"min\": 9.78545454655345}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007232991515844027,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.00830738756815947, \"min\": 0.0055232672487608835}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Gitter499",
            "username": "Gitter499",
            "email": "rafayel.amirkhanyan@gmail.com"
          },
          "committer": {
            "name": "Gitter499",
            "username": "Gitter499",
            "email": "rafayel.amirkhanyan@gmail.com"
          },
          "id": "b694688d04b43a92885a5c9eea581ea498c7d78f",
          "message": "Make no-stack a default benchmark config, drop --no-stack flag",
          "timestamp": "2026-07-28T18:57:10Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/b694688d04b43a92885a5c9eea581ea498c7d78f"
        },
        "date": 1785280907587,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 363.32224431488663,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1191.006603369432, \"min\": 230.40942949963062}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11164603219446573,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23478843402807253, \"min\": 0.09803580873085359}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.088609983958726,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.184210494854195, \"min\": 5.503904128206504}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022299242633215983,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0025753791399129432, \"min\": 0.001921982509121552}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 335.04536488650143,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1362.3718685736062, \"min\": 199.78881041182112}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.10454091936179064,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.3760131207516547, \"min\": 0.04638625959244143}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 722.0375007021203,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 32726.25073090872, \"min\": 291.5803257485277}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.147224286395369,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.8701526669906556, \"min\": 0.10545323274200175}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 6.966107299545479,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22.841619134376703, \"min\": 5.863029857596094}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002322522569418936,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002711866058772696, \"min\": 0.002003252209242476}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 300.82180208638505,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 430.7531679725465, \"min\": 189.67479336672946}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.10286674681102127,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.1150698875239701, \"min\": 0.03777784886013274}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3891.6552024732828,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7781.780673317043, \"min\": 683.5373373894671}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.46468170729570735,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7553365216915878, \"min\": 0.24832536307981104}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.347211470602193,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.966919894649976, \"min\": 10.453436305496826}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003160933560095545,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004216532868320062, \"min\": 0.0021624095980445233}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 2271.388778884567,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 4597.793795645017, \"min\": 377.2022443170053}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.26880551801727504,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.44872092847214984, \"min\": 0.1370355050863434}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3424.962660448844,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 176531.88539701235, \"min\": 299.84109439736915}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.4343286472050669,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 15.567587374269594, \"min\": 0.13020960844277704}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.768899575388818,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.170019213327333, \"min\": 6.211350555673463}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.003480831486177929,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004037788010358512, \"min\": 0.0018565507547685213}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3393.394753590276,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 176973.97948628647, \"min\": 288.5856080202066}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.42483286385331404,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 15.606573749716416, \"min\": 0.0693461412525736}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 388.5729203910052,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1429.5516732876313, \"min\": 264.0935461377748}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.1502527043096294,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2998770060752506, \"min\": 0.13075010075643842}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.141464089988387,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 41.91327380485148, \"min\": 9.520084452424443}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.005136431153337544,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.008473488591052014, \"min\": 0.004302159396931722}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 362.7372759872712,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1603.9308805408227, \"min\": 258.0848293670475}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14430222324293362,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.5187271259635091, \"min\": 0.06636694649355769}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 732.5544957303786,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 33671.7266253752, \"min\": 277.3258187698256}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.17938074599083423,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.4791116621607157, \"min\": 0.13926606352241017}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.122870297015158,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 120.09371293437397, \"min\": 9.519556948723338}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005330760057897514,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.008842009428272676, \"min\": 0.004552335953466078}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 310.1507606094159,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 755.6221481312447, \"min\": 257.60104507733735}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1385865221650149,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.15348733413205173, \"min\": 0.05563337159572305}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4351.8116630465975,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8976.641114408494, \"min\": 698.2826257312161}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5576056809449649,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.9152481319612937, \"min\": 0.3128380975523225}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 51.23473549990808,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 84.18069045143186, \"min\": 18.61109826754701}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008460186998298565,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.010180701843342771, \"min\": 0.007805022447598574}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 2488.793581701975,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 5128.565550878373, \"min\": 400.360291354516}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.31938943328983416,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.4999397338078655, \"min\": 0.18008417121830336}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 1959.7461369058562,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 90228.48584065176, \"min\": 307.8247105407039}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.36177987318187355,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.41799259419018, \"min\": 0.169209133002362}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.781092529287967,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 88.29804351603262, \"min\": 10.149992723063683}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007877357031680453,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.00960603207300674, \"min\": 0.006805069750044604}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 1848.8245118893913,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 85870.18141201144, \"min\": 303.5192741734177}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.34572689582983246,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-stack\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.011378495973862, \"min\": 0.0979141913503852}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "523f9bd84a9a921c5178a627bebd38e6474df23b",
          "message": "Added carets to error messages to indicate the column location. (#296)\n\n* Added carets to error messages to indicate the column location.\n\n* fmt + clippy\n\n* Fully rely on saturating_sub + bless.",
          "timestamp": "2026-07-28T17:23:32-04:00",
          "tree_id": "bc3a923010ef40748fc9b9c53526cbf962a05525",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/523f9bd84a9a921c5178a627bebd38e6474df23b"
        },
        "date": 1785286405463,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 365.31428045303454,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1152.6287916758922, \"min\": 263.5916975819514}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11107827094997694,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.22669523640462647, \"min\": 0.09852836726942012}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.476460281150401,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.229857009369749, \"min\": 6.158547361758479}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0023268438068070932,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0028289523372787956, \"min\": 0.0019843862070742634}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 714.1625835400679,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 32162.216442853904, \"min\": 266.43271499218935}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.14539915118464808,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.754284184636786, \"min\": 0.10053138920961852}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.227849588509104,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22.585430096181362, \"min\": 5.543811075810929}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0024130772043601083,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0031786648572923906, \"min\": 0.0019341544146269079}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3976.5909627193487,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8047.393056914184, \"min\": 658.1301668492929}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.45933654483229097,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7475496038854386, \"min\": 0.24427961490073324}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.66309763272688,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.39145469125448, \"min\": 10.317794532652643}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0031669476048233804,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004250709808559677, \"min\": 0.0021609935446596433}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3336.3761759014733,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 171516.6107260281, \"min\": 291.264557779935}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.4151492751479325,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.529910520451816, \"min\": 0.12393555241081812}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.18638776504486,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.2200505883335, \"min\": 6.318046969995989}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0037023685695516005,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004458841142810405, \"min\": 0.0017559057110003243}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 410.70008600447994,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1449.746759841134, \"min\": 308.4130183519117}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14225381915312305,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2889196068832989, \"min\": 0.12167459844735432}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.10866195277158,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 34.40037736274943, \"min\": 9.543069755618136}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004609845922730267,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006516138855348378, \"min\": 0.00384561286113346}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 780.0873854430125,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 35988.84977085587, \"min\": 236.32269393336648}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1657334898379543,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.268565597710055, \"min\": 0.12082648155421721}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.019475174727967,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 108.60010643458939, \"min\": 8.216602637108805}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.0046725621231949056,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007069408809255507, \"min\": 0.003649582962162389}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4418.041230923669,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9174.030656089832, \"min\": 731.1822077805658}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5231931720319885,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8568165532342121, \"min\": 0.2992618750672948}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.087605844971094,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 78.21728356304389, \"min\": 18.322478783083668}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007359100633312278,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008336061522915269, \"min\": 0.0064199725277950224}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2191.166306159843,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 102076.38502168539, \"min\": 189.44063815495429}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.35684197877207974,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.487920734253628, \"min\": 0.16463534436957425}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.574189975921625,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 88.8912090729366, \"min\": 5.8080983260314}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007151395160470591,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008444732127465255, \"min\": 0.006243646830913384}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "523f9bd84a9a921c5178a627bebd38e6474df23b",
          "message": "Added carets to error messages to indicate the column location. (#296)\n\n* Added carets to error messages to indicate the column location.\n\n* fmt + clippy\n\n* Fully rely on saturating_sub + bless.",
          "timestamp": "2026-07-28T21:23:32Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/523f9bd84a9a921c5178a627bebd38e6474df23b"
        },
        "date": 1785301487355,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 376.3633836922022,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1203.3806320070894, \"min\": 299.9443269500021}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11549673834970249,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2364750797101252, \"min\": 0.10166498760655561}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.073759353309771,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.315211465130005, \"min\": 5.984941899362905}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002218721983761028,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0026264569542515095, \"min\": 0.001932517259713169}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 714.8585895074755,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 31077.04614771759, \"min\": 299.3966989914585}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1503226550073954,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.8076833598345625, \"min\": 0.1098501676291944}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 6.853094190320051,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.49655039706648, \"min\": 5.904595247432504}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002275079320620743,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002672828264993943, \"min\": 0.0020652534012488275}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3917.3676730943644,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7788.943647781215, \"min\": 708.9074467433984}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.46527568375052725,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7529439170484445, \"min\": 0.2528125585189825}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.482780874050498,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.398360879681128, \"min\": 10.520617057953952}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003080193433471178,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004095437696512061, \"min\": 0.0021911103201269545}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3278.572529118449,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 167373.37744099362, \"min\": 314.2318378478994}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.42107811497790043,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.548567987566253, \"min\": 0.1325286321114437}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.810646619897584,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.126603447750753, \"min\": 6.326678837334287}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0034712259145454156,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004130817826425979, \"min\": 0.0018812096580095214}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 388.5357643460121,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1371.75558553961, \"min\": 174.768428834832}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.1497795975438434,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.3013732985860716, \"min\": 0.12666928590951515}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.221643797319485,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.96197697571836, \"min\": 5.773357659017075}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0051485252219971855,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.008128637163157143, \"min\": 0.0044033069985542645}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 737.0684089673323,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 33821.27893408908, \"min\": 301.00244817320237}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.17951701497774508,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.5234456702860473, \"min\": 0.14070743656730103}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.431909864969562,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 123.30162748474247, \"min\": 10.049127579841235}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005403759023761837,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.009199680432604452, \"min\": 0.004701450703433874}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4209.689967158621,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8704.759626301968, \"min\": 705.2915109103501}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5607852781606113,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8916801777260962, \"min\": 0.31777492330791535}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 49.62833157240321,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 80.02754000222524, \"min\": 18.512414002578126}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008419420899504499,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.009228891798078809, \"min\": 0.007649886963498762}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 1936.0295683980964,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 88749.79518836043, \"min\": 311.0966139625203}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.36210221835877476,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.270303955914303, \"min\": 0.16947557234349123}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.752316399184597,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 84.12230102238638, \"min\": 10.315511096927878}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007996204584766312,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.009198468093487793, \"min\": 0.006590368676098066}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6a0c11237e14d4a2beda6bc75470c0f9e02fba1a",
          "message": "Disable debug assertions in Miri.",
          "timestamp": "2026-07-29T10:05:04-04:00",
          "tree_id": "94a006f9273ea63fd3f7c8b82615e2756a87091b",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/6a0c11237e14d4a2beda6bc75470c0f9e02fba1a"
        },
        "date": 1785346149173,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 369.6049925400731,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1212.4106820302866, \"min\": 260.44718363122934}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11372860957416865,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.25238591783678943, \"min\": 0.09900260019212244}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.749372605132132,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.738219538616972, \"min\": 6.290009594034538}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0024316023070648264,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002939234440737523, \"min\": 0.002131030818876014}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 716.7490845427575,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 31796.94182802541, \"min\": 246.86240513451082}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1491008493152113,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.842361618162665, \"min\": 0.10718162498288358}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.495434346726401,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.264114397909303, \"min\": 5.567391119041255}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0025094914194961158,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0032257514633393923, \"min\": 0.0020796033216905502}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3910.1097914031093,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7725.207456449075, \"min\": 663.9240708929402}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4693092967093309,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7677826044128706, \"min\": 0.248284193220331}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.210128411907494,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 24.986108106700165, \"min\": 10.31299390324838}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.00321361699000312,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004318611068588051, \"min\": 0.0020927459052411494}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3212.353283071412,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 163679.2173959168, \"min\": 300.60768158600223}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.4355764553082135,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 15.438515225868066, \"min\": 0.13845639874779977}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.426211983148379,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.034400641301186, \"min\": 6.484969886440389}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0038043944970263676,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004607520575678123, \"min\": 0.001927050735508886}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 408.3502578915736,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1392.5484234090993, \"min\": 331.79547908239294}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14522487863121136,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.29661059446987564, \"min\": 0.1306732081336148}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 12.871970487534327,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 34.17237742307839, \"min\": 9.94701800262673}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004625815194187244,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.00700270496372664, \"min\": 0.003943042663830543}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 755.9707911515812,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 34305.83529973891, \"min\": 308.30136182354215}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.17589378557504406,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.618864845565948, \"min\": 0.13537882946754293}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 12.878414484804336,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 106.26077899551535, \"min\": 9.446361521286272}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004889293705205956,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.00811181585122125, \"min\": 0.004121520416541991}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4270.070692714079,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8502.430688323333, \"min\": 732.1654185758448}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5361065701848625,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8339553222977392, \"min\": 0.31097070201538685}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.42713225508821,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 77.85672335272021, \"min\": 19.10125093473151}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007845704061079721,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008686122155611955, \"min\": 0.0070237240300877}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2227.751877965497,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 104121.88789285398, \"min\": 327.1815769898792}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.3656380997487462,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.989788343219882, \"min\": 0.17450349690993203}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.70527282996532,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 87.71274932385393, \"min\": 10.238314430304335}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007241953421994177,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008618233598227618, \"min\": 0.006093376983528013}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Gitter499",
            "username": "Gitter499",
            "email": "rafayel.amirkhanyan@gmail.com"
          },
          "committer": {
            "name": "Gitter499",
            "username": "Gitter499",
            "email": "rafayel.amirkhanyan@gmail.com"
          },
          "id": "e6819b06cfa5d13e05f67b690cd52f7efc27e61c",
          "message": "feat(bench): Parallelize across crates and architectures",
          "timestamp": "2026-07-29T18:10:11Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/e6819b06cfa5d13e05f67b690cd52f7efc27e61c"
        },
        "date": 1785353004625,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 727.0232001551891,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 32763.18517434543, \"min\": 299.35678658258945}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.14905604335106706,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.8588825116420264, \"min\": 0.10739031721094579}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 6.798291167752717,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 23.555521552797398, \"min\": 5.702646514843228}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002270787412295248,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0025908649875247647, \"min\": 0.0020554310657387035}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3949.8903067441934,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7869.311032966687, \"min\": 680.3486804276832}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.465401956120829,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7534738475196532, \"min\": 0.2492527399503074}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.567747112943653,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.31181982934994, \"min\": 10.696033912067714}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003160526812124855,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004291033503887299, \"min\": 0.0021219146301259795}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3217.09701559955,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 164520.96172048352, \"min\": 298.1850706366383}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.42006237140538916,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 14.783960885776578, \"min\": 0.1294233461021427}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.264940078932007,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.220699357136926, \"min\": 6.221317585981858}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0037506554999952573,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004270587603848198, \"min\": 0.001803216357329531}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 390.2865616186715,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1318.6858442133357, \"min\": 310.6449373327657}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.15083719462218448,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.30136238159841194, \"min\": 0.13223621631820914}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.476184153863954,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 35.36398534392218, \"min\": 10.585347338999828}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.005259654774079976,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.007808823342243949, \"min\": 0.004394968450617087}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 751.6860642314671,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 34629.72107840972, \"min\": 297.60995650204194}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1768927284803634,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.368831789814366, \"min\": 0.1369201010456639}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.58382423423447,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 123.43805632219194, \"min\": 10.033715869261012}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005346639395168399,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.009175703971225541, \"min\": 0.004372007837788929}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2225.251754298001,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 104621.11863554003, \"min\": 308.5791724110197}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.3533678908188343,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.5173199467539, \"min\": 0.16209923966915332}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.58143711851604,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 84.35588934485934, \"min\": 10.02786899826119}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.0072065819191320345,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008012512864324476, \"min\": 0.005901918061958358}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4363.404518262221,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8768.554553617263, \"min\": 725.8937108101316}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5250863199580984,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8105137284887461, \"min\": 0.30308143507638746}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 47.93923393376508,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 76.12693906699327, \"min\": 17.25749406173323}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007370126091575838,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008063766653900949, \"min\": 0.0068014003119461625}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 360.165950003418,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1152.8311462712345, \"min\": 272.3564776039093}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11159758434167474,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23661449885624083, \"min\": 0.0943379112081347}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.6574565299743,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 10.892747969763404, \"min\": 6.462452337080945}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002428539068401104,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002887635963725887, \"min\": 0.0019939103121977735}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ebdca4bd45cd0b2127a3053fa045226d4e1dbcd5",
          "message": "Update to 1.99.0 (#280)\n\n* Update to 1.99.0\n\n* fetch_update -> try_update\n\n* Do not force alignment of pointers that are aligned to a multiple of the provenance alignment.\n\n* Fix alignment for mem retags.\n\n* Update test output for fail-dep.\n\n* bless\n\n* Remove `LL:CC` for stdlib allocator shims.\n\n* fmt",
          "timestamp": "2026-07-29T11:46:29-04:00",
          "tree_id": "99309b389c23232923d1d6f98756497265558560",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/ebdca4bd45cd0b2127a3053fa045226d4e1dbcd5"
        },
        "date": 1785358600315,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 379.5937110187952,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1527.9456670677928, \"min\": 223.90588727709428}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14901062814673768,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.3015136067050957, \"min\": 0.1277605167753162}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 9.091441313266136,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 19.41243684842076, \"min\": 5.991862136646993}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0037050715184971327,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.00483284309941832, \"min\": 0.002934235811437397}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 933.5177418215173,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 51821.47200311639, \"min\": 216.8286899394859}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.19308472169956517,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 3.5165490979317946, \"min\": 0.13255093121784475}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 8.69095707690315,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 37.66360931369681, \"min\": 5.658302885085315}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.0039558403944656645,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.005821658552387483, \"min\": 0.002555811833152311}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4103.599781775383,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9367.856621817278, \"min\": 540.7712796431595}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5709262000938234,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.9264872759823607, \"min\": 0.3086398125169357}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 20.68436975926959,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 36.04536923234672, \"min\": 9.447490728693577}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.0044888330594530625,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.006956826638190552, \"min\": 0.002800530022112845}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 3278.4349034800953,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 166444.58840822562, \"min\": 227.5952758872155}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.4869055837869962,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 15.212704730421407, \"min\": 0.1752627022739549}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 9.73850839967829,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 30.23886963270232, \"min\": 5.717146343772815}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.005879758474706226,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.007640818272522639, \"min\": 0.002327841668192147}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 370.924239120745,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1242.0778458863886, \"min\": 303.5880806065699}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11936604750098044,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.26177852406068786, \"min\": 0.10462309247915909}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.374564419245827,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 12.06516541289178, \"min\": 6.060486652962808}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002426816780165191,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0029031045213177837, \"min\": 0.002063465609047995}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 714.0878272164341,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 32622.60016612356, \"min\": 272.99039868515644}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.1506589275046792,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.859194418857649, \"min\": 0.1066658469935005}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.35726026577345,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24.327353395646217, \"min\": 6.07715668605022}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0025869829406627446,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0031446919121219004, \"min\": 0.002132160916058413}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3929.8562587926767,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7865.318090919018, \"min\": 649.7418488508852}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.4718676695064901,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7865230607237883, \"min\": 0.2569493880913515}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.325850389984705,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.57207507136345, \"min\": 10.074902592422532}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0032542242816388667,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004682772207084643, \"min\": 0.002112532184357289}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3406.6964060103096,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 175570.5255313986, \"min\": 296.8460410916054}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.4526749196559265,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 16.233332562716235, \"min\": 0.14048514984068802}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.122348605661804,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.86208978067494, \"min\": 6.4898748547108065}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.003867227169973701,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.0044830851459159785, \"min\": 0.0019245882898852305}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67717700+Gitter499@users.noreply.github.com",
            "name": "Rafayel Amirkhanyan",
            "username": "Gitter499"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "97f4e1db1bdc967fdf990b2b09d292c151b5192e",
          "message": "feat(bench): Parallelize across crates and architectures (#299)",
          "timestamp": "2026-07-29T15:30:52-04:00",
          "tree_id": "54cb75c4eeada0fc588aa9393af3f9edef4378c4",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/97f4e1db1bdc967fdf990b2b09d292c151b5192e"
        },
        "date": 1785362595566,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3926.9447189514103,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7726.410434045723, \"min\": 705.7057990897349}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.47662684567699276,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7716483441111562, \"min\": 0.26210320605780213}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.94573316365081,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.426113866128613, \"min\": 10.711611080207907}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.003345699369873525,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004919973508957174, \"min\": 0.002214227879997206}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3274.075804642009,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 167583.58022367957, \"min\": 301.0408824324695}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.4530071544360261,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 16.2106398072343, \"min\": 0.14129862851193117}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.16635011512908,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.42072036324883, \"min\": 6.812514549094463}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0038280681547687495,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004367824195495528, \"min\": 0.0019973310403582803}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 702.3285829509244,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 31150.181187220056, \"min\": 284.77376041957257}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.15042380203550826,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.762138905831395, \"min\": 0.10766625967526734}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.670383281842216,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24.038228795740885, \"min\": 6.388734409722749}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.002673874217032913,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.0029671410932922584, \"min\": 0.0021315101374509192}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 369.0417421805773,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1211.7813711335218, \"min\": 281.6154928148438}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11774913253935426,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2606731105861846, \"min\": 0.10282110144639921}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.653580378445806,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.742460806519835, \"min\": 6.0349956302427605}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002502952394623556,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003010064115388469, \"min\": 0.002090883777730226}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 406.22237154783636,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1437.406413512779, \"min\": 243.6002886657906}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14115304514383048,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.29053318142604345, \"min\": 0.125815468844868}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 13.022399627810767,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 33.85425071794934, \"min\": 7.270009320943202}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004584353776189231,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.006748767981849075, \"min\": 0.003882665026021435}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2362.7462150817078,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 111475.86123481228, \"min\": 297.4605082247929}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.37366508245520075,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 9.274023629913431, \"min\": 0.17385722889307864}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 16.097934302089374,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 87.49582347281917, \"min\": 10.217949067506092}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007405409089782119,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008456951185910696, \"min\": 0.006277273115680496}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4424.343361583929,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8967.76371153023, \"min\": 748.8921932918355}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5469025405107455,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8736139035729218, \"min\": 0.31379368453501305}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 47.95042123949513,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 76.30660885076364, \"min\": 19.064036939503655}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.007679517913112512,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.008623981707512891, \"min\": 0.006831609809865028}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 792.0139622497867,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 36718.699958895624, \"min\": 311.80924011404016}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1809672274293173,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.620503468451705, \"min\": 0.14070422476935499}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 13.191591820384318,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 115.04556974106856, \"min\": 9.60228730154852}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.005044626907582635,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.008210457202296333, \"min\": 0.004368835663656228}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Rafayel Amirkhanyan",
            "username": "Gitter499",
            "email": "67717700+Gitter499@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "97f4e1db1bdc967fdf990b2b09d292c151b5192e",
          "message": "feat(bench): Parallelize across crates and architectures (#299)",
          "timestamp": "2026-07-29T19:30:52Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/97f4e1db1bdc967fdf990b2b09d292c151b5192e"
        },
        "date": 1785379534297,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3901.1805919196045,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7672.71606888783, \"min\": 666.4453415464031}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.45631006324452505,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7463661489852732, \"min\": 0.25022008161890874}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.4041195260956,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 25.88929142776992, \"min\": 10.560642856435987}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.00312913537126423,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.00417822279832604, \"min\": 0.0020435250393785803}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 377.7978272830192,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1312.2919210838827, \"min\": 243.61689710275832}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11643095803380334,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.255232209033251, \"min\": 0.10305857085706979}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.003562495107063,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.912964429743278, \"min\": 4.983554819098048}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002209337046151558,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0025703152049647345, \"min\": 0.001981203783172288}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 713.8753521276664,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 32123.500243764134, \"min\": 289.29129891550093}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.14913043078048335,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.915770096946129, \"min\": 0.10494344790300192}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 6.962880295259616,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 24.43895040259729, \"min\": 5.895388918292988}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0023521152194172345,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002609903297824853, \"min\": 0.0020913924498248897}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3228.686663213796,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 164528.26712686894, \"min\": 312.2878849935818}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.4401099704582692,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 15.61590569779738, \"min\": 0.13664670385989153}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 7.772850191435958,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 22.683021949164306, \"min\": 6.177910423874773}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0034863708764491107,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.003991105719867011, \"min\": 0.0019668499658556248}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4221.133465699821,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 8461.68317150661, \"min\": 736.3082799997601}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5469941507195399,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.852334487291672, \"min\": 0.3210729401270826}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 48.79043616805689,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 78.20389844138141, \"min\": 18.604147949422842}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.008121985612106768,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.011954027706074984, \"min\": 0.007121532312770238}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 404.1543934124085,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1460.6016729802989, \"min\": 295.43977188211363}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14378275006327218,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.29645878454814995, \"min\": 0.12374041051223078}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 12.814999916716916,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.15230640751666, \"min\": 9.061828479635661}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004610100546925119,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.007246258165875124, \"min\": 0.003885800934621373}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 782.9842847273457,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 36162.0743865158, \"min\": 314.14369656579277}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.17985762770779273,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.602217986215892, \"min\": 0.14064740157986047}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 12.997213061053602,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 110.55776815685424, \"min\": 10.009939238313875}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004980493654768962,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007955722056722755, \"min\": 0.004391559886952838}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 2374.910741565913,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 112212.87155383908, \"min\": 329.00447398013284}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.37037940535118175,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 9.19763444281075, \"min\": 0.1731908746352002}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.957112533805304,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 86.60014221863393, \"min\": 10.411366918992096}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.00724744820995649,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.008329167617819867, \"min\": 0.006416792979885629}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Gitter499",
            "username": "Gitter499",
            "email": "rafayel.amirkhanyan@gmail.com"
          },
          "committer": {
            "name": "Gitter499",
            "username": "Gitter499",
            "email": "rafayel.amirkhanyan@gmail.com"
          },
          "id": "81ba8866b8126883a648739e59d0b084ebbd0ba5",
          "message": "bench: swap aho-corasick for thread_local",
          "timestamp": "2026-07-30T15:03:39Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/81ba8866b8126883a648739e59d0b084ebbd0ba5"
        },
        "date": 1785427976347,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "log@0.4.29 - aarch64-unknown-linux-gnu",
            "value": 313.6582838881525,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.4.29\", \"crate\": \"log\", \"max\": 326.2570858949663, \"min\": 300.7354407664821}"
          },
          {
            "name": "log@0.4.29 - aarch64-unknown-linux-gnu",
            "value": 0.20425083994077894,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.4.29\", \"crate\": \"log\", \"max\": 0.21097855739202576, \"min\": 0.19762487274840107}"
          },
          {
            "name": "log@0.4.29 - aarch64-unknown-linux-gnu",
            "value": 7.035970768055322,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.4.29\", \"crate\": \"log\", \"max\": 10.701743457870515, \"min\": 6.196753445635529}"
          },
          {
            "name": "log@0.4.29 - aarch64-unknown-linux-gnu",
            "value": 0.004580211132103141,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.4.29\", \"crate\": \"log\", \"max\": 0.006920427153719962, \"min\": 0.004077563830529298}"
          },
          {
            "name": "ppv-lite86@0.2.21 - aarch64-unknown-linux-gnu",
            "value": 333.0866102071443,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.21\", \"crate\": \"ppv-lite86\", \"max\": 335.2753526245118, \"min\": 330.89786778977674}"
          },
          {
            "name": "ppv-lite86@0.2.21 - aarch64-unknown-linux-gnu",
            "value": 0.19311833943862544,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.21\", \"crate\": \"ppv-lite86\", \"max\": 0.19717881661282485, \"min\": 0.18905786226442603}"
          },
          {
            "name": "ppv-lite86@0.2.21 - aarch64-unknown-linux-gnu",
            "value": 7.164082782592972,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.21\", \"crate\": \"ppv-lite86\", \"max\": 7.252953374540813, \"min\": 7.075212190645131}"
          },
          {
            "name": "ppv-lite86@0.2.21 - aarch64-unknown-linux-gnu",
            "value": 0.004152482328003141,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.21\", \"crate\": \"ppv-lite86\", \"max\": 0.004161003653013667, \"min\": 0.0041439610029926155}"
          },
          {
            "name": "socket2@0.6.2 - aarch64-unknown-linux-gnu",
            "value": 313.02586669891707,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.6.2\", \"crate\": \"socket2\", \"max\": 325.13291110942555, \"min\": 297.9301606194214}"
          },
          {
            "name": "socket2@0.6.2 - aarch64-unknown-linux-gnu",
            "value": 0.18661244497557838,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.6.2\", \"crate\": \"socket2\", \"max\": 0.18997171624437387, \"min\": 0.1839177711278737}"
          },
          {
            "name": "socket2@0.6.2 - aarch64-unknown-linux-gnu",
            "value": 7.084378712363813,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.6.2\", \"crate\": \"socket2\", \"max\": 7.591723719455966, \"min\": 6.39652251925518}"
          },
          {
            "name": "socket2@0.6.2 - aarch64-unknown-linux-gnu",
            "value": 0.004224916495490462,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.6.2\", \"crate\": \"socket2\", \"max\": 0.004620791692918182, \"min\": 0.003753336167707123}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 3930.970820094672,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 7823.687107321719, \"min\": 690.0754771743301}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.47795031034231605,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.7787487801469896, \"min\": 0.25874639369248564}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 18.545212156333417,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 26.105054236582713, \"min\": 10.448079107742538}"
          },
          {
            "name": "matchers@0.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.0032451044413111365,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.004360117726574202, \"min\": 0.0021925894322906477}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 712.8035003978138,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 30882.281305182456, \"min\": 301.7998854381017}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.15545259059656935,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.8604622941406563, \"min\": 0.11320884132127615}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 7.157281150589098,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 22.96828035129382, \"min\": 6.120663643642854}"
          },
          {
            "name": "rand@0.10.1 - aarch64-unknown-linux-gnu",
            "value": 0.0024714870460046455,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.002696981738468183, \"min\": 0.0021274302651696385}"
          },
          {
            "name": "scopeguard@1.2.0 - aarch64-unknown-linux-gnu",
            "value": 317.4848056477235,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.2.0\", \"crate\": \"scopeguard\", \"max\": 325.09023964862644, \"min\": 306.92390269409526}"
          },
          {
            "name": "scopeguard@1.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.22230853709131077,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.2.0\", \"crate\": \"scopeguard\", \"max\": 0.2239652917707242, \"min\": 0.2214551248757107}"
          },
          {
            "name": "scopeguard@1.2.0 - aarch64-unknown-linux-gnu",
            "value": 7.002271152477356,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.2.0\", \"crate\": \"scopeguard\", \"max\": 7.341816964072143, \"min\": 6.674010006104266}"
          },
          {
            "name": "scopeguard@1.2.0 - aarch64-unknown-linux-gnu",
            "value": 0.004902501485076606,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.2.0\", \"crate\": \"scopeguard\", \"max\": 0.005088694106173128, \"min\": 0.004765561019328083}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 3328.000118960625,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 170736.60391004785, \"min\": 304.96864466049004}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.4334179687973542,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 15.079008497371372, \"min\": 0.13676584556056595}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 8.12914683666563,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 23.209557538247804, \"min\": 6.435872390168062}"
          },
          {
            "name": "bit-vec@0.9.1 - aarch64-unknown-linux-gnu",
            "value": 0.0037987715656805587,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.004311612086809961, \"min\": 0.0018905929290436668}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 367.6445809083293,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1204.4442572112885, \"min\": 256.9510824119151}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.11695260696691452,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.239151708289155, \"min\": 0.09886090374803924}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.895196499744982,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 11.74667957256215, \"min\": 5.810198441719565}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002576728178153067,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003076094239142633, \"min\": 0.0020729505534981566}"
          },
          {
            "name": "either@1.15.0 - aarch64-unknown-linux-gnu",
            "value": 339.66875929289546,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.15.0\", \"crate\": \"either\", \"max\": 516.3183396747663, \"min\": 303.3640718238772}"
          },
          {
            "name": "either@1.15.0 - aarch64-unknown-linux-gnu",
            "value": 0.2052580288308787,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.15.0\", \"crate\": \"either\", \"max\": 0.2777906564268834, \"min\": 0.1908272405182245}"
          },
          {
            "name": "either@1.15.0 - aarch64-unknown-linux-gnu",
            "value": 7.339044582706834,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.15.0\", \"crate\": \"either\", \"max\": 7.992714446052731, \"min\": 6.967491546727166}"
          },
          {
            "name": "either@1.15.0 - aarch64-unknown-linux-gnu",
            "value": 0.004479144410829529,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.15.0\", \"crate\": \"either\", \"max\": 0.004999640822648754, \"min\": 0.004027764251373501}"
          },
          {
            "name": "thread_local@1.1.9 - aarch64-unknown-linux-gnu",
            "value": 339.1602115818859,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.1.9\", \"crate\": \"thread_local\", \"max\": 578.0045821382992, \"min\": 275.21271787765113}"
          },
          {
            "name": "thread_local@1.1.9 - aarch64-unknown-linux-gnu",
            "value": 0.19704887904331647,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.1.9\", \"crate\": \"thread_local\", \"max\": 0.21120781383642526, \"min\": 0.1270281331773021}"
          },
          {
            "name": "thread_local@1.1.9 - aarch64-unknown-linux-gnu",
            "value": 7.603685855585562,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.1.9\", \"crate\": \"thread_local\", \"max\": 8.42492539996803, \"min\": 6.9136028914219105}"
          },
          {
            "name": "thread_local@1.1.9 - aarch64-unknown-linux-gnu",
            "value": 0.00468266075782082,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"1.1.9\", \"crate\": \"thread_local\", \"max\": 0.005528771630907359, \"min\": 0.0018515468195023873}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 444.5359631537289,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 1423.2746948508013, \"min\": 343.276754699083}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.14340588533316895,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2922429172535319, \"min\": 0.1270948789533876}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 11.125996146028198,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 18.130917489765856, \"min\": 9.575495245868959}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.003695917513246702,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.004915471517981799, \"min\": 0.0029142209079303046}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 4625.19627002561,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 9802.138104443511, \"min\": 611.9816955240775}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.5459260529356742,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.8585547068121689, \"min\": 0.3069222792321975}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 23.753888041519108,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 35.89989327343315, \"min\": 11.50875401263557}"
          },
          {
            "name": "matchers@0.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.004369501569402182,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.0\", \"crate\": \"matchers\", \"max\": 0.0064857904723490765, \"min\": 0.003003606884375921}"
          },
          {
            "name": "log@0.4.29 - x86_64-unknown-linux-gnu",
            "value": 303.1691240154542,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.4.29\", \"crate\": \"log\", \"max\": 316.061540679643, \"min\": 197.8845222124909}"
          },
          {
            "name": "log@0.4.29 - x86_64-unknown-linux-gnu",
            "value": 0.2553531448560388,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.4.29\", \"crate\": \"log\", \"max\": 0.2647801830883385, \"min\": 0.24163602036994083}"
          },
          {
            "name": "log@0.4.29 - x86_64-unknown-linux-gnu",
            "value": 10.98322335076786,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.4.29\", \"crate\": \"log\", \"max\": 14.959156799688518, \"min\": 6.641922027532083}"
          },
          {
            "name": "log@0.4.29 - x86_64-unknown-linux-gnu",
            "value": 0.009233931188466295,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.4.29\", \"crate\": \"log\", \"max\": 0.01243182138830052, \"min\": 0.008260502309970769}"
          },
          {
            "name": "scopeguard@1.2.0 - x86_64-unknown-linux-gnu",
            "value": 310.3988812004772,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.2.0\", \"crate\": \"scopeguard\", \"max\": 318.7226985890263, \"min\": 304.9504817945395}"
          },
          {
            "name": "scopeguard@1.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.2807925670138434,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.2.0\", \"crate\": \"scopeguard\", \"max\": 0.28577449339729805, \"min\": 0.27687225228628004}"
          },
          {
            "name": "scopeguard@1.2.0 - x86_64-unknown-linux-gnu",
            "value": 11.111850499530025,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.2.0\", \"crate\": \"scopeguard\", \"max\": 11.998603575432924, \"min\": 10.14472587486683}"
          },
          {
            "name": "scopeguard@1.2.0 - x86_64-unknown-linux-gnu",
            "value": 0.010048571158270096,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.2.0\", \"crate\": \"scopeguard\", \"max\": 0.010701069868843923, \"min\": 0.009344284372834785}"
          },
          {
            "name": "socket2@0.6.2 - x86_64-unknown-linux-gnu",
            "value": 329.3983153592428,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.6.2\", \"crate\": \"socket2\", \"max\": 342.0218634532007, \"min\": 320.89591606519764}"
          },
          {
            "name": "socket2@0.6.2 - x86_64-unknown-linux-gnu",
            "value": 0.2288525796227938,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.6.2\", \"crate\": \"socket2\", \"max\": 0.23794090644817428, \"min\": 0.21862010390284353}"
          },
          {
            "name": "socket2@0.6.2 - x86_64-unknown-linux-gnu",
            "value": 10.999593350252644,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.6.2\", \"crate\": \"socket2\", \"max\": 12.04177779902172, \"min\": 10.049933747592425}"
          },
          {
            "name": "socket2@0.6.2 - x86_64-unknown-linux-gnu",
            "value": 0.007640581724564574,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.6.2\", \"crate\": \"socket2\", \"max\": 0.008501066393060364, \"min\": 0.006998277002656547}"
          },
          {
            "name": "ppv-lite86@0.2.21 - x86_64-unknown-linux-gnu",
            "value": 317.63605338951794,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.21\", \"crate\": \"ppv-lite86\", \"max\": 329.7119534555491, \"min\": 305.56015332348676}"
          },
          {
            "name": "ppv-lite86@0.2.21 - x86_64-unknown-linux-gnu",
            "value": 0.22660008022926814,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.21\", \"crate\": \"ppv-lite86\", \"max\": 0.2280317535294698, \"min\": 0.22516840692906645}"
          },
          {
            "name": "ppv-lite86@0.2.21 - x86_64-unknown-linux-gnu",
            "value": 10.854735769060586,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.21\", \"crate\": \"ppv-lite86\", \"max\": 11.32573194549067, \"min\": 10.383739592630501}"
          },
          {
            "name": "ppv-lite86@0.2.21 - x86_64-unknown-linux-gnu",
            "value": 0.007742397109452962,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.2.21\", \"crate\": \"ppv-lite86\", \"max\": 0.007832978114586778, \"min\": 0.007651816104319147}"
          },
          {
            "name": "either@1.15.0 - x86_64-unknown-linux-gnu",
            "value": 354.60449207270796,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.15.0\", \"crate\": \"either\", \"max\": 526.6759554053717, \"min\": 313.82088407448055}"
          },
          {
            "name": "either@1.15.0 - x86_64-unknown-linux-gnu",
            "value": 0.24681751578167846,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.15.0\", \"crate\": \"either\", \"max\": 0.3310759058881913, \"min\": 0.2249991202833966}"
          },
          {
            "name": "either@1.15.0 - x86_64-unknown-linux-gnu",
            "value": 11.947136133245621,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.15.0\", \"crate\": \"either\", \"max\": 12.96721383166377, \"min\": 10.393875009533845}"
          },
          {
            "name": "either@1.15.0 - x86_64-unknown-linux-gnu",
            "value": 0.008378815771633288,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.15.0\", \"crate\": \"either\", \"max\": 0.009230629917099033, \"min\": 0.00739879739442951}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 753.9665339129217,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 34374.84378788612, \"min\": 171.4646902852885}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.1721502743151921,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 2.3237796946967313, \"min\": 0.12856359006504733}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 12.704668208121081,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 107.07100923987592, \"min\": 5.5376281935402805}"
          },
          {
            "name": "rand@0.10.1 - x86_64-unknown-linux-gnu",
            "value": 0.004836914337222172,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.10.1\", \"crate\": \"rand\", \"max\": 0.007667587801230791, \"min\": 0.003962055311441306}"
          },
          {
            "name": "thread_local@1.1.9 - x86_64-unknown-linux-gnu",
            "value": 347.3317886887116,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.1.9\", \"crate\": \"thread_local\", \"max\": 488.02781068858394, \"min\": 262.7742098929635}"
          },
          {
            "name": "thread_local@1.1.9 - x86_64-unknown-linux-gnu",
            "value": 0.24180328934113055,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.1.9\", \"crate\": \"thread_local\", \"max\": 0.28916150928123435, \"min\": 0.11810982534310878}"
          },
          {
            "name": "thread_local@1.1.9 - x86_64-unknown-linux-gnu",
            "value": 9.374934640816033,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.1.9\", \"crate\": \"thread_local\", \"max\": 10.743364676967909, \"min\": 7.096038939991729}"
          },
          {
            "name": "thread_local@1.1.9 - x86_64-unknown-linux-gnu",
            "value": 0.006928292462974793,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"1.1.9\", \"crate\": \"thread_local\", \"max\": 0.009885247076948942, \"min\": 0.0019208855453945368}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 1944.3091803245832,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 89595.24393260873, \"min\": 308.45211040605994}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.3614099595771961,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 8.376584612709545, \"min\": 0.17368426943468304}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 15.8921763118507,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 92.44826983888443, \"min\": 9.898298967033012}"
          },
          {
            "name": "bit-vec@0.9.1 - x86_64-unknown-linux-gnu",
            "value": 0.007956853328525203,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.9.1\", \"crate\": \"bit-vec\", \"max\": 0.010224520820414418, \"min\": 0.006148146592437173}"
          }
        ]
      }
    ]
  }
}