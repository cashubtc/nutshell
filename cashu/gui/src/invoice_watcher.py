import asyncio
from typing import Callable, List

from cashu.core.base import Invoice
from cashu.wallet.wallet import Wallet


class _InvoiceData:
    invoice: Invoice
    wallet: Wallet

    def __init__(self, invoice: Invoice, wallet: Wallet):
        self.invoice = invoice
        self.wallet = wallet


class InvoiceWatcher:
    _instance = None
    _invData: List[_InvoiceData] = []
    _callbacks: List[Callable] = []
    _task = None
    _task_running = False

    def __new__(cls, *args, **kwargs):
        if not isinstance(cls._instance, cls):
            cls._instance = super(InvoiceWatcher, cls).__new__(cls, *args, **kwargs)

        return cls._instance

    def add_invoice(self, invoice: Invoice, wallet: Wallet):
        self._invData.append(_InvoiceData(invoice=invoice, wallet=wallet))
        self._start_background_task()

    def _remove_invoice(self, invoice: _InvoiceData):
        self._invData.remove(invoice)
        if len(self._invData) == 0:
            self._stop_background_task()

    def add_callback(self, callback: Callable):
        self._callbacks.append(callback)
        self._start_background_task()

    def remove_callback(self, callback: Callable):
        self._callbacks.remove(callback)
        if len(self._callbacks) == 0:
            self._stop_background_task()

    def _start_background_task(self):
        if (
            not self._task_running
            and len(self._callbacks) > 0
            and len(self._invData) > 0
        ):
            self._task = asyncio.create_task(self._check_invoices())
            self._task_running = True

    def _stop_background_task(self):
        self._task.cancel()
        self._task_running = False

    async def _check_invoices(self):
        while len(self._invData) > 0:
            for data in self._invData:
                if await self._check_invoice(data):
                    for callback in self._callbacks:
                        await callback(data.invoice)

                    self._remove_invoice(data)

            await asyncio.sleep(1)

    async def _check_invoice(self, iData: _InvoiceData):
        try:
            await iData.wallet.mint(iData.invoice.amount, hash=iData.invoice.hash)
            return True
        except Exception as e:
            if "invoice not paid" in str(e):
                return False

            raise
