# WordPress.org plugin assets

Everything in this directory is synced to the `assets/` directory of the
WordPress.org SVN repository by `.github/workflows/deploy-to-wordpress-org.yml`.

It is **not** part of the plugin: the release ZIP is built from an allow list
that never names this directory, so nothing here can reach a user's site. These
are the images the public plugin page at
https://wordpress.org/plugins/vokull-security-center renders.

Assets are not versioned — the SVN `assets/` directory only ever holds the
current set, and a change here goes live with the next deploy.

| File | Purpose | Status |
| --- | --- | --- |
| `icon-256x256.png` | Plugin icon, search results and the update screen | shipped |
| `icon.svg` | Vector icon, preferred by the directory when present | shipped |
| `banner-772x250.png` | Header on the plugin page | missing — the page falls back to a plain grey header |
| `banner-1544x500.png` | Retina header | missing |
| `screenshot-1.png` … | One per `== Screenshots ==` entry in `readme.txt`, in order | missing — `readme.txt` has no Screenshots section yet |

The images under `screenshots/` in the repository root are for the GitHub
README. They can become directory screenshots, but only renamed to
`screenshot-N.png` here **and** described by a matching numbered list under a
`== Screenshots ==` heading in `readme.txt` — the directory pairs them by index,
not by filename.

Full specification: https://developer.wordpress.org/plugins/wordpress-org/plugin-assets/
