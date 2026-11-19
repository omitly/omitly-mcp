/**
 * omitly#1940: the REAL engine output (omitly-redact 5.6.x, debug build, trial licence, fake page content) for a
 * redaction whose only image, a CCITT scan, the engine had to remove whole: `redact`'s `audit` and the saved file's
 * `verify_seal` reply. The lowering of a lost scan is on three presented surfaces only (the app's result card, the delivery receipt's view and verdict, the
 * certificate), so these carry the verdict the sealed overall maps to: pass, safe_to_send, not blocking. A lowered
 * verdict beside a pass overall would read as an error to the parsers below (omitly#1943 is the signed follow-up).
 */
export const LONE_SCAN_REDACT_AUDIT: unknown = {
  "auditSchema": "omitly.audit/v2",
  "auditV2Overall": "pass",
  "blocking": false,
  "decisionChannel": "cli",
  "disclosures": [
    "page 1: image /Im0 met a redaction region and could not be redacted precisely (unsupported bits-per-component 1), so the whole image was removed",
    "Omitly removed 1 unused item(s) from this file's page resources (forms, patterns, graphics states or fonts that no page used), including on pages you did not redact."
  ],
  "license": "trial",
  "licensedTo": null,
  "metadataScrubbed": true,
  "regions": [
    {
      "bbox": {
        "height": 138.0,
        "width": 420.0,
        "x": 50.0,
        "y": 556.0
      },
      "page": 0,
      "reason_code": "PII.TEST",
      "timestamp": "2026-11-19T05:02:48.595609Z",
      "verification": {
        "result": "pass"
      }
    }
  ],
  "result": {
    "blocking": false,
    "canWrite": false,
    "checked": [
      {
        "text": "No text found under any black or white box (1 page)"
      },
      {
        "text": "No hidden layers, embedded files or comments"
      },
      {
        "text": "Single version: no earlier saves recoverable"
      },
      {
        "text": "Page text readable on the only page (no scanned pages)"
      },
      {
        "text": "No scripts, automatic actions or page thumbnails"
      },
      {
        "text": "Document properties and metadata read"
      },
      {
        "text": "Areas Omitly redacted"
      },
      {
        "text": "Omitly's detector found no identifiers it recognises in the page text"
      }
    ],
    "checkedAt": "2026-11-19T05:02:48.595609Z",
    "decidedBy": [
      {
        "text": "Decided by: not recorded. The Omitly engine was run directly from the command line."
      },
      {
        "text": "This is what the sealed report records. It does not prove who made the decision."
      }
    ],
    "decisionChannel": "cli",
    "decisions": [],
    "detectionProfile": [
      {
        "text": "Detection profile: Omitly built-in detector (all regions), revision 1."
      },
      {
        "text": "Profile content SHA-256: 7c8b435d7a44f801a102681a7e5b7e50ae90126119e319fbca00e230b7a9a4f5"
      }
    ],
    "information": [
      {
        "pages": [
          1
        ],
        "text": "A redacted area met an image that could not be redacted precisely on page 1, so the whole image was removed."
      }
    ],
    "notChecked": [
      {
        "text": "Bookmarks, tooltips, labels and alternate text: none in this file"
      },
      {
        "text": "Form fields: none in this file"
      },
      {
        "text": "Text Omitly removed: none in this file"
      },
      {
        "text": "Searchable text on scanned pages: none in this file"
      },
      {
        "text": "Text inside images is not read: this check does no OCR."
      },
      {
        "text": "Pictures under a box (a box drawn over a scanned image) are not checked."
      }
    ],
    "omitlyVersion": "0.1.0",
    "pagesRead": 1,
    "pagesTotal": 1,
    "problems": [],
    "producer": null,
    "reasons": [],
    "review": [],
    "sealKey": [
      {
        "text": "Sealed with a one-time key: there is no known fingerprint to compare it with."
      }
    ],
    "sha256": "5a645b2e0a0152f0b914f0ebc64f85ffa8ecfbdf29c529aafb216e446ffc6ce5",
    "sizeBytes": 30936,
    "state": "safe_to_send",
    "summary": "Every mandatory check that applies to this file passed. 1 page checked. 4 of the 15 checks did not apply to this file (below)."
  },
  "sealFingerprint": "c1:76:fa:9f:1d:09:c7:5f:aa:4e:41:ff:4c:b8:45:34",
  "userVerdict": "safe_to_send",
  "verdict": "pass",
  "warnings": [
    "Marked as evaluation output. The redaction and verification are complete; activate or renew a licence for unmarked audit output."
  ]
};

export const LONE_SCAN_VERIFY_SEAL: Record<string, unknown> = {
  "allPassed": null,
  "auditV2Overall": "pass",
  "auditV2Recognized": true,
  "auditV2SealValid": true,
  "auditV2ValidationError": null,
  "blocking": false,
  "decisionChannel": "cli",
  "detectionProfile": {
    "content_sha256": "7c8b435d7a44f801a102681a7e5b7e50ae90126119e319fbca00e230b7a9a4f5",
    "recognised": {
      "id": "omitly.detector.builtin-all-regions",
      "name": "Omitly built-in detector (all regions)",
      "revision": 1
    }
  },
  "inputSha256": null,
  "legacyUnboundVerdict": null,
  "licenseProvenance": null,
  "metadataScrubbed": null,
  "ok": true,
  "omitlyVersion": null,
  "outputFilename": null,
  "outputSha256": null,
  "pageCount": null,
  "policyEpoch": 2,
  "regionCount": null,
  "reportSchema": "omitly.audit/v2",
  "result": {
    "blocking": false,
    "canWrite": false,
    "checked": [
      {
        "text": "No text found under any black or white box (1 page)"
      },
      {
        "text": "No hidden layers, embedded files or comments"
      },
      {
        "text": "Single version: no earlier saves recoverable"
      },
      {
        "text": "Page text readable on the only page (no scanned pages)"
      },
      {
        "text": "No scripts, automatic actions or page thumbnails"
      },
      {
        "text": "Document properties and metadata read"
      },
      {
        "text": "Areas Omitly redacted"
      },
      {
        "text": "Omitly's detector found no identifiers it recognises in the page text"
      }
    ],
    "checkedAt": "2026-11-19T05:02:48.595609Z",
    "decidedBy": [
      {
        "text": "Decided by: not recorded. The Omitly engine was run directly from the command line."
      },
      {
        "text": "This is what the sealed report records. It does not prove who made the decision."
      }
    ],
    "decisionChannel": "cli",
    "decisions": [],
    "detectionProfile": [
      {
        "text": "Detection profile: Omitly built-in detector (all regions), revision 1."
      },
      {
        "text": "Profile content SHA-256: 7c8b435d7a44f801a102681a7e5b7e50ae90126119e319fbca00e230b7a9a4f5"
      }
    ],
    "information": [
      {
        "pages": [
          1
        ],
        "text": "A redacted area met an image that could not be redacted precisely on page 1, so the whole image was removed."
      }
    ],
    "notChecked": [
      {
        "text": "Verify does not re-run the checks. It confirms the file is unchanged since it was sealed and shows what the sealed report records."
      }
    ],
    "omitlyVersion": "0.1.0",
    "pagesRead": 1,
    "pagesTotal": 1,
    "problems": [],
    "producer": null,
    "reasons": [],
    "review": [],
    "sealKey": [
      {
        "text": "Sealed with a one-time key: there is no known fingerprint to compare it with."
      }
    ],
    "sha256": "5a645b2e0a0152f0b914f0ebc64f85ffa8ecfbdf29c529aafb216e446ffc6ce5",
    "sizeBytes": 30936,
    "state": "safe_to_send",
    "summary": "The sealed report records that every check that applies to this file passed, and the file is unchanged since it was sealed. What was and was not checked is listed below."
  },
  "schemaSupported": false,
  "sealExcludesSignatureValue": false,
  "sealFingerprint": null,
  "sealKeyKind": "one_time",
  "sealLegs": [
    {
      "alg_id": 1,
      "result": "valid"
    },
    {
      "alg_id": 2,
      "result": "valid"
    }
  ],
  "sealReason": null,
  "sealRemoved": false,
  "sealValid": null,
  "sealVerdict": "valid",
  "sealVersion": "v2",
  "sealWarnings": [],
  "sessionRecord": {
    "finalisation": {
      "detection_profile_sha256": "7c8b435d7a44f801a102681a7e5b7e50ae90126119e319fbca00e230b7a9a4f5",
      "region_emptiness": "pass",
      "removed_byte_survivor": "not_applicable",
      "removed_content": "not_found"
    },
    "operations": [
      {
        "at": "2026-11-19T05:02:48.701Z",
        "op": "redact"
      },
      {
        "at": "2026-11-19T05:02:48.701Z",
        "op": "verify_regions"
      },
      {
        "at": "2026-11-19T05:02:48.742Z",
        "op": "inspect"
      },
      {
        "at": "2026-11-19T05:02:48.742Z",
        "op": "detector_rescan"
      },
      {
        "at": "2026-11-19T05:02:48.742Z",
        "op": "build_report"
      },
      {
        "op": "seal"
      }
    ]
  },
  "sourceFilename": null,
  "userVerdict": "safe_to_send",
  "verdict": "unsupported_schema",
  "warnings": [
    "unsupported audit report schema \"omitly.audit/v2\"; no report claims were trusted"
  ]
};
