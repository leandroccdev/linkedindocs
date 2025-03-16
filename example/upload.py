# Uploads minimal example

from linkedindocs import (
        AttachmentCreator,
        ContentVisibility,
        Cookies,
        CookiesFileLoader,
        Document,
        Publication,
        set_user_agent
    )
# Use this module if you wants to catch particular exceptions
# import linkedin.exceptions
import logging

# Todo: set up the cookies.json file
COOKIES_FILE = "cookies.json"
# Todo: set up the user agent of the browser with you normally visits linkedin
USER_AGENT = ""
set_user_agent(USER_AGENT)

def main() -> None:
    # Sets logging to INFO level
    logging.getLogger("linkedindocs").setLevel(logging.INFO)

    # Read cookies file
    try:
        c: Cookies = CookiesFileLoader(COOKIES_FILE).cookies
        # Initialize attachme creator handler
        att: AttachmentCreator = AttachmentCreator(c)
        p: Publication = Publication(
                document=Document("Sample.pdf", "sample.pdf"),
                text_comment="This is a sample document...",
                visibility=ContentVisibility.ANYONE
            )
        att.send(p)
    except Exception as e:
        logging.error(e)
        exit(1)
    else:
        assert bool(p.urn)
        assert bool(p.url)
        print(f"Publication URN: {p.urn}")
        print(f"Publication URL: {p.url}")

if __name__ == "__main__":
    main()