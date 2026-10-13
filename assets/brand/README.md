# OkieOTSec brand assets

The logo, icons and colour tokens used by RuleTruss (and by OT Triage), from the OkieOTSec brand kit v1.1. `ruletruss/web/brand/` holds the few SVGs the web page serves.

- `svg/`: the vector originals used here (lockups, shields, app tile, wordmarks, README badge). The Oklahoma outline is
  traced from US Census Bureau boundary data and must not be redrawn by hand.
- `icons/`, `header/`, `lockup/`: PNGs rendered from those SVGs at the sizes the application needs : the window icon (the app tile), the shield beside the title, and the lockup in the About view.
  `icons/favicon.ico` is the Windows icon.
- `readme/` and `social/`: the lockups shown in the README and the 1200 x 630 link-preview card.
- `tokens.json` and `tokens.css`: the colours and fonts the application's themes are built from.

To rebuild the PNGs from the SVGs: `rsvg-convert -w <size> -h <size> svg/okieotsec-app-tile.svg -o icons/tile-<size>.png`
(and likewise for the shields by height and the lockups by width).

## Rights

The OkieOTSec name, logo and the other files in `assets/brand/` are © okieotsec and are **not** covered by the MIT
licence, which applies to the code only.

- You may use them, unmodified, to refer to or link to this project (for example in an article, a talk or a link to
  the repository).
- **Forks and modified versions may not use them.** If you fork or redistribute a changed version of RuleTruss, remove
  or replace the contents of `assets/brand/` and use your own name and logo, so that it cannot be mistaken for the
  original or for something OkieOTSec endorses. The application starts normally without the folder.
- The name and links shown in the window (the header, About section and footer of the web page) belong to
  the same brand, so a fork should change those too.
