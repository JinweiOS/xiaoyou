"""Send access-code updates without blocking authentication requests."""
import asyncio
import json
import logging
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


def send_webhook(url, payload):
    request = Request(url, data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                      headers={'Content-Type': 'application/json'}, method='POST')
    with urlopen(request, timeout=8) as response:
        return json.load(response)


class WebhookNotifier:
    def __init__(self, url='', sender=None, retry_delays=(2, 5)):
        self.urls = list(dict.fromkeys(part.strip() for part in url.split(',') if part.strip()))
        for index, target in enumerate(self.urls, 1):
            parsed = urlsplit(target)
            if parsed.scheme != 'https' or parsed.netloc != 'qyapi.weixin.qq.com' or parsed.path != '/cgi-bin/webhook/send':
                raise ValueError(f'WECHAT_WEBHOOK_URL entry {index} must be an official WeCom webhook URL')
        self.sender = sender or send_webhook
        self.retry_delays = retry_delays
        self.queue = asyncio.Queue(maxsize=1)
        self.latest = None
        self.status = {'status': 'disabled' if not self.urls else 'pending', 'total': len(self.urls)}

    def enqueue(self, code, generated_at, expires_at, *, resend=False):
        if not self.urls:
            return
        if (resend and self.status['status'] == 'pending' and self.latest
                and self.latest['code'] == code and self.latest['generated_at'] == generated_at):
            return
        self.latest = {'code': code, 'generated_at': generated_at, 'expires_at': expires_at, 'resend': resend}
        self.status = {'status': 'pending', 'generated_at': generated_at.isoformat(), 'total': len(self.urls)}
        if self.queue.full():
            self.queue.get_nowait()
            self.queue.task_done()
        self.queue.put_nowait(self.latest)

    async def deliver(self, job, index, url, payload, semaphore):
        async with semaphore:
            for attempt in range(len(self.retry_delays) + 1):
                if job is not self.latest:
                    return None
                error = None
                try:
                    result = await asyncio.to_thread(self.sender, url, payload)
                    if not isinstance(result, dict) or result.get('errcode') != 0:
                        error = 'WeCom rejected the notification'
                except Exception as exc:
                    # Exception text may contain webhook secrets. Never expose URLs.
                    error = type(exc).__name__
                if job is not self.latest:
                    return None
                if error is None:
                    logger.info('Access-code notification sent to target %d', index)
                    return {'target': index, 'status': 'sent', 'attempts': attempt + 1}
                if attempt < len(self.retry_delays):
                    await asyncio.sleep(self.retry_delays[attempt])
                else:
                    logger.warning('Access-code notification failed for target %d: %s', index, error)
                    return {'target': index, 'status': 'failed', 'attempts': attempt + 1, 'error': error}

    async def run(self):
        while True:
            job = await self.queue.get()
            try:
                title = '校友网站当前认证码（补发）' if job['resend'] else '校友网站认证码已更新'
                note = '本次为补发通知，认证码和登录会话保持不变。' if job['resend'] else '旧认证码及旧登录会话已失效。'
                content = (f"{title}\n认证码：{job['code']}\n"
                           f"生成时间：{job['generated_at']:%Y-%m-%d %H:%M:%S}\n"
                           f"有效至：{job['expires_at']:%Y-%m-%d %H:%M:%S}（北京时间）\n"
                           f"{note}")
                semaphore = asyncio.Semaphore(4)
                payload = {'msgtype': 'text', 'text': {'content': content}}
                results = await asyncio.gather(*(self.deliver(job, index, url, payload, semaphore)
                                                for index, url in enumerate(self.urls, 1)))
                if job is self.latest:
                    succeeded = sum(result['status'] == 'sent' for result in results)
                    status = 'sent' if succeeded == len(results) else ('partial' if succeeded else 'failed')
                    self.status = {'status': status, 'generated_at': job['generated_at'].isoformat(),
                                   'total': len(results), 'succeeded': succeeded,
                                   'failed': len(results) - succeeded, 'targets': results}
                    if status == 'failed' and len(results) == 1:
                        self.status['error'] = results[0]['error']
            finally:
                self.queue.task_done()
