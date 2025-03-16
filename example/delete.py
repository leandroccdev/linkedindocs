from linkedindocs import (
        Cookies,
        CookiesFileLoader,
        DocumentDeleter,
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
        # Initialize document deleter
        dd: DocumentDeleter = DocumentDeleter(c)
        p: Publication = Publication(
                # Todo: set the urn
                # # https://linkedin.com/posts/name-lastname-user-id_title-activity-[publication-urn]-hash?rcm=hash
                # urn (int): [publication-urn]
                urn=
            )
        dd.delete(p)
    except Exception as e:
        logging.error(e)
        exit(1)

if __name__ == "__main__":
    main()