from linkedindocs import (
        DocumentDownloader,
        Publication,
        set_user_agent
    )
# Use this module if you wants to catch particular exceptions
# import linkedin.exceptions
from os.path import exists
import logging

# Todo: set up the user agent of the browser with you normally visits linkedin
USER_AGENT = ""
set_user_agent(USER_AGENT)

def main() -> None:
    # Sets logging to INFO level
    logging.getLogger("linkedindocs").setLevel(logging.INFO)
    output_file: str = "downloaded.pdf"

    try:
        # Initialize document downloader handler
        dd: DocumentDownloader = DocumentDownloader()
        p: Publication = Publication(
                # Todo: set up the publication path
                # https://linkedin.com/posts/[path=[name-lastname]-[user-id]_title-activity-[publication-urn]-hash]?rcm=hash
                # path: [name-lastname]-[user-id]_title-activity-[publication-urn]-hash
                path=""
            )
        dd.download(p, output_file)
    except Exception as e:
        logging.error(e)
        exit(1)
    else:
        assert exists(output_file)

if __name__ == "__main__":
    main()