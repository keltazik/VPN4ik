"""Rebuild SVG and native WPF curves from the original ornament.

Development dependencies: vtracer==0.6.15 and Pillow==12.3.0.
Install with: python -m pip install --target .tools/vectorizer vtracer==0.6.15 Pillow==12.3.0
Then run this script from any working directory. No dependency is added to the app.
"""
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.tools/vectorizer'))
import vtracer
from PIL import Image

OUT = ROOT / 'docs/ornament'
OUT.mkdir(parents=True, exist_ok=True)
WORK = ROOT / '.tools/ornament'
WORK.mkdir(parents=True, exist_ok=True)

# Trace at the original resolution to retain fine floral detail and colors.
vtracer.convert_image_to_svg_py(
    str(ROOT / 'source/VPNyan/VPNyan/ornament.png'), str(WORK / 'traced.svg'),
    colormode='color', hierarchical='stacked', mode='spline', filter_speckle=4,
    color_precision=6, layer_difference=16, corner_threshold=60,
    length_threshold=3.5, max_iterations=10, splice_threshold=45, path_precision=2)

svg = ET.parse(WORK / 'traced.svg').getroot()
width, height = svg.get('width'), svg.get('height')
NS = 'http://www.w3.org/2000/svg'
ET.register_namespace('', NS)
svg.set('viewBox', f'0 0 {width} {height}')
svg.set('role', 'img')
title = ET.Element(f'{{{NS}}}title')
title.text = 'VPN4ik — векторный орнамент'
svg.insert(0, title)
paths = [element for element in svg if element.tag == f'{{{NS}}}path']
assert paths and all(element.tag in (f'{{{NS}}}path', f'{{{NS}}}title') for element in svg)
ET.ElementTree(svg).write(OUT / 'ornament.svg', encoding='utf-8', xml_declaration=True)

# WPF renders the same paths directly, without an SVG parser or bitmap at runtime.
lines = [
    '<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"',
    ' xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"',
    ' xmlns:po="http://schemas.microsoft.com/winfx/2006/xaml/presentation/options">',
    '  <DrawingImage x:Key="OrnamentVector" po:Freeze="True">',
    '    <DrawingImage.Drawing>', '      <DrawingGroup>',
    f'        <GeometryDrawing Brush="Transparent" Geometry="M0,0 H{width} V{height} H0 Z"/>',
]
for element in paths:
    transform = element.get('transform', '')
    if transform:
        # This VTracer version emits translations only; fail on other transforms.
        assert transform.startswith('translate(') and transform.endswith(')'), transform
        values = transform[10:-1].replace(',', ' ').split()
        x, y = values[0], values[1] if len(values) > 1 else '0'
        lines += [
            '        <DrawingGroup>',
            f'          <DrawingGroup.Transform><TranslateTransform X="{x}" Y="{y}"/></DrawingGroup.Transform>',
        ]
    lines.append(f'          <GeometryDrawing Brush="{element.get("fill")}" Geometry="F1 {element.get("d")}"/>')
    if transform:
        lines.append('        </DrawingGroup>')
lines += ['      </DrawingGroup>', '    </DrawingImage.Drawing>', '  </DrawingImage>']

# Pointer hit testing needs the silhouette, not thousands of colored details.
# Trace the original alpha to a separate, frozen geometry in the same coordinates.
image = Image.open(ROOT / 'source/VPNyan/VPNyan/ornament.png').convert('RGBA')
silhouette = Image.new('RGBA', image.size, (255, 255, 255, 0))
silhouette.putalpha(image.getchannel('A').point(lambda alpha: 255 if alpha >= 16 else 0))
silhouette.save(WORK / 'silhouette.png')
vtracer.convert_image_to_svg_py(
    str(WORK / 'silhouette.png'), str(WORK / 'silhouette.svg'),
    colormode='color', hierarchical='stacked', mode='spline', filter_speckle=4,
    color_precision=6, layer_difference=16, corner_threshold=60,
    length_threshold=3.5, max_iterations=10, splice_threshold=45, path_precision=2)
hit_paths = list(ET.parse(WORK / 'silhouette.svg').getroot())
lines.append('  <GeometryGroup x:Key="OrnamentHitGeometry" po:Freeze="True" FillRule="Nonzero">')
for element in hit_paths:
    assert element.tag == f'{{{NS}}}path'
    transform = element.get('transform', '')
    matrix = ''
    if transform:
        assert transform.startswith('translate(') and transform.endswith(')'), transform
        values = transform[10:-1].replace(',', ' ').split()
        x, y = values[0], values[1] if len(values) > 1 else '0'
        matrix = f' Transform="1,0,0,1,{x},{y}"'
    lines.append(f'    <PathGeometry FillRule="Nonzero" Figures="{element.get("d")}"{matrix}/>')
lines += ['  </GeometryGroup>', '</ResourceDictionary>']
(ROOT / 'source/VPNyan/VPNyan/Ornament.xaml').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(f'Wrote SVG and WPF ornament: {len(paths)} color paths, {len(hit_paths)} silhouette paths, {width} x {height} viewBox.')
