import os

import discord
from dotenv import load_dotenv

from bot_utils import *
from file_scanner import scan_file

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
GUILD = os.getenv('DISCORD_GUILD')

client = discord.Client()

@client.event
async def on_ready():
    guild = discord.utils.get(client.guilds, name=GUILD)
    print(f'{client.user} has connected to Discord!')
    print(f'Guild is: {guild.name}, {guild.id}')

''' On client message, the bot should check whether there are extensions and/or links '''
@client.event 
async def on_message(message):
    #ignore own messages
    if message.author == client.user:
        return 
    if message.content == "test":
        response = "Test succesful"
        await message.channel.send(response)
    #for faster testing, exit when user types "bye"
    if message.content == "bye":
        exit(0)
    #Check if links exist in message
    urls = findURLs(message.content)
    #If there is an attachment
    if message.attachments is not None:
        for attachment in message.attachments:
            print("\nAttachment detected\n")
            print(attachment.filename)
            #Save the attachment
            await attachment.save(attachment.filename)
            #Check if the attachment is secure
            is_secure = await scan_file(attachment.filename)
            #Lastly, delete the file 
            os.remove(attachment.filename)
            

client.run(TOKEN)
