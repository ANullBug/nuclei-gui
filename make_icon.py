# -*- coding: utf-8 -*-
"""生成 Nuclei GUI 应用图标（Win11 风格，主题蓝色）。

输出: icons/app.ico（含 16/24/32/48/64/128/256 多尺寸）
       icons/app.png （256 预览图）
"""
import os

from PIL import Image, ImageDraw

SIZE = 256
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def make_icon(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / 256.0  # 缩放系数

    # 圆角方形背景（Win11 风格圆角，约 18% 边长）
    radius = int(52 * s)
    # 垂直渐变：上 #3E9BFF -> 下 #0B63D8
    for y in range(size):
        t = y / size
        color = lerp((0x3E, 0x9B, 0xFF), (0x0B, 0x63, 0xD8), t)
        d.line([(0, y), (size, y)], fill=color + (255,))
    # 用圆角遮罩裁剪
    mask = Image.new("L", (size, size), 0)
    md = ImageDraw.Draw(mask)
    md.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    img.putalpha(mask)

    # 图案：靶心 + 扫描射线（nuclei 扫描意象）
    cx, cy = size * 0.5, size * 0.48
    line_w = max(3, int(9 * s))
    # 外环
    d.ellipse([cx - 64 * s, cy - 64 * s, cx + 64 * s, cy + 64 * s],
              outline=(255, 255, 255, 255), width=line_w)
    # 内环
    d.ellipse([cx - 34 * s, cy - 34 * s, cx + 34 * s, cy + 34 * s],
              outline=(255, 255, 255, 255), width=line_w)
    # 中心点
    r = max(3, int(11 * s))
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 255, 255, 255))

    # 一条扫描射线（中心到右上，模拟扫描旋转）
    import math
    ang = math.radians(-40)
    lx = cx + 78 * s * math.cos(ang)
    ly = cy + 78 * s * math.sin(ang)
    d.line([(cx, cy), (lx, ly)], fill=(255, 255, 255, 255), width=line_w)
    # 射线末端小箭头点
    ar = max(3, int(8 * s))
    d.ellipse([lx - ar, ly - ar, lx + ar, ly + ar], fill=(255, 255, 255, 255))
    return img


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    base = make_icon(256)
    base.save(os.path.join(OUT_DIR, "app.png"))

    # 多尺寸 ico
    sizes = [16, 24, 32, 48, 64, 128, 256]
    imgs = [base.resize((sz, sz), Image.LANCZOS) for sz in sizes]
    ico_path = os.path.join(OUT_DIR, "app.ico")
    imgs[0].save(ico_path, format="ICO", sizes=[(sz, sz) for sz in sizes],
                 append_images=imgs[1:])
    print("icon written:", ico_path, os.path.getsize(ico_path), "bytes")


if __name__ == "__main__":
    main()
