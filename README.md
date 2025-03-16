## linkedindocs
This module allows you to creates and deletes publications with PDF documents as attachments.  Additionally, it allows for the download of attachment documents from public publications.

#### How do i get account cookies?
You can export cookies from your account using Cookies-Editor browser extension (Which is available for chromium/firefox browsers).
- [Chromium based browsers](https://chromewebstore.google.com/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm?pli=1)
- [Firefox based browsers](https://addons.mozilla.org/es-CL/firefox/addon/cookie-editor/)

#### Where do i put the json string?
The json string exported from Cookie-Editor extension must be saved at `cookie.json` file as it is. (See the examples to know where set up the cookie.json file at code).

#### Python version
Currently it's has been tested over Python3.13 but it should be compatible with Python3.8.

#### Installation
By now this is the only way to install this module with pip.

`pip install git+https://github.com/leandroccdev/linkedindocs`

#### Documentation?

Please see the `example` folder.

#### Requires

- colorama
- requests
- tqdm

`pip install -r requirements.txt`