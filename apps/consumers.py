# secureapp/consumers.py
from channels.generic.websocket import AsyncWebsocketConsumer
import json

class ProgressConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data=None, bytes_data=None):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']

        # 可以在这里更新任务进度，并发送进度信息给客户端
        await self.send(text_data=json.dumps({
            'progress': message
        }))
