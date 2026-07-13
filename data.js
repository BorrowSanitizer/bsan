window.BENCHMARK_DATA = {
  "lastUpdate": 1783982967326,
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
      }
    ]
  }
}