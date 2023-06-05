import flet as f

from cashu.gui.src.nut_works_app import NutWorksApp


async def main(page: f.Page):

    page.title = "NutWorks App"
    page.vertical_alignment = f.MainAxisAlignment.CENTER
    page.theme_mode = "dark"

    app = NutWorksApp(page)
    await app.init()


f.app(target=main)
