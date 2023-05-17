import json
import logging
import sys
from time import time

import requests


def slack_recipe_block(recipe, website):
    if not recipe.verified:
        task_title = (
            f"*{ recipe.name } failed trust verification* \n"
            + recipe.results["message"]
        )
    elif recipe.error:
        task_title = f"*Failed to import { recipe.name }* \n"
        if not recipe.results["failed"]:
            task_title += "Unknown error"
        else:
            task_title += f'Error: {recipe.results["failed"][0]["message"]} \n'
            if "No releases found for repo" in task_title:
                # Just no updates
                return
    elif recipe.updated:
        task_title = (
            f"*Imported {recipe.name} {str(recipe.updated_version)}* \n"
            + f'*Catalogs:* {recipe.results["imported"][0]["catalogs"]} \n'
            + f'*Package Path:* `{recipe.results["imported"][0]["pkg_repo_path"]}` \n'
            + f'*Pkginfo Path:* `{recipe.results["imported"][0]["pkginfo_path"]}` \n'
        )
    else:
        # Also no updates
        return

    try:
        icon = recipe.plist["Input"]["pkginfo"]["icon_name"]
    except:
        icon = recipe.name + ".png"

    block = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": task_title,
                },
                "accessory": {
                    "type": "image",
                    "image_url": f"https://{website}/icons/{icon}",
                    "alt_text": recipe.name,
                },
            }
        ]
    }
    return block


def slack_summary_block(applications):
    app_string = "\n".join(applications.keys())
    app_version = "\n".join(applications.values())

    block = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":new: The following items have been updated",
                    "emoji": True,
                },
            },
            {"type": "divider"},
        ],
        "attachments": [
            {
                "mrkdwn_in": ["text"],
                "color": "00FF00",
                "ts": time(),
                "fields": [
                    {
                        "title": "Application",
                        "short": True,
                        "value": app_string,
                    },
                    {
                        "title": "Version",
                        "short": True,
                        "value": app_version,
                    },
                ],
                "footer": "Autopkg Automated Run",
                "footer_icon": "https://avatars.slack-edge.com/2020-10-30/1451262020951_7067702535522f0c569b_48.png",
            }
        ],
    }
    return block


def slack_alert(data, url):
    if not url:
        print("Skipping Slack notification - webhook is missing!")
        return

    byte_length = str(sys.getsizeof(data))
    headers = {"Content-Type": "application/json", "Content-Length": byte_length}

    response = requests.post(url, data=json.dumps(data), headers=headers)
    if response.status_code != 200:
        logging.warning(
            f"WARNING: Request to slack returned an error {response.status_code}, the response is: {response.text}. Payload: {json.dumps(data)}"
        )
