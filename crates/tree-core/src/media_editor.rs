//! Pre-send media editor model.
//!
//! This module is renderer/GUI independent. It describes a deterministic edit
//! recipe that an Android/iOS/Desktop renderer can apply to a local plaintext
//! image before the resulting bytes enter the encrypted media pipeline.
//! No editor operation changes the attachment cryptographic identity.

use serde::{Deserialize, Serialize};

use crate::error::TreeError;

pub const EDITOR_VERSION: u8 = 1;
pub const MAX_TEXT_LAYERS: usize = 64;
pub const MAX_DRAW_STROKES: usize = 4096;
pub const MAX_FILTERS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f32,
    pub y: f32,
}

impl Point {
    pub fn validate(self) -> Result<(), TreeError> {
        if !self.x.is_finite() || !self.y.is_finite()
            || !(0.0..=1.0).contains(&self.x) || !(0.0..=1.0).contains(&self.y) {
            return Err(TreeError::Usage("editor point is not finite".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rotation {
    Deg0,
    Deg90,
    Deg180,
    Deg270,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct CropRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl CropRect {
    pub fn validate(self) -> Result<(), TreeError> {
        if !self.x.is_finite() || !self.y.is_finite()
            || !self.width.is_finite() || !self.height.is_finite()
            || self.width <= 0.0 || self.height <= 0.0
            || self.x < 0.0 || self.y < 0.0
        {
            return Err(TreeError::Usage("invalid editor crop rectangle".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImageAdjustments {
    /// Exposure in stops, roughly -4.0 .. +4.0.
    pub exposure: f32,
    /// Contrast multiplier around 1.0, bounded to 0.0 .. 3.0.
    pub contrast: f32,
    /// Saturation multiplier around 1.0, bounded to 0.0 .. 3.0.
    pub saturation: f32,
    /// Temperature shift, normalized -1.0 .. +1.0.
    pub temperature: f32,
    /// Highlights/shadows correction, normalized -1.0 .. +1.0.
    pub highlights: f32,
    pub shadows: f32,
    /// Detail/sharpening amount, normalized 0.0 .. 2.0.
    pub sharpness: f32,
}

impl Default for ImageAdjustments {
    fn default() -> Self {
        Self {
            exposure: 0.0,
            contrast: 1.0,
            saturation: 1.0,
            temperature: 0.0,
            highlights: 0.0,
            shadows: 0.0,
            sharpness: 0.0,
        }
    }
}

impl ImageAdjustments {
    pub fn validate(self) -> Result<(), TreeError> {
        if !self.exposure.is_finite()
            || !self.contrast.is_finite()
            || !self.saturation.is_finite()
            || !self.temperature.is_finite()
            || !self.highlights.is_finite()
            || !self.shadows.is_finite()
            || !self.sharpness.is_finite()
            || !(-4.0..=4.0).contains(&self.exposure)
            || !(0.0..=3.0).contains(&self.contrast)
            || !(0.0..=3.0).contains(&self.saturation)
            || !(-1.0..=1.0).contains(&self.temperature)
            || !(-1.0..=1.0).contains(&self.highlights)
            || !(-1.0..=1.0).contains(&self.shadows)
            || !(0.0..=2.0).contains(&self.sharpness)
        {
            return Err(TreeError::Usage("image adjustment is outside allowed range".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TextLayer {
    pub text: String,
    /// Position is normalized to the source image [0,1] coordinate space.
    pub position: Point,
    pub scale: f32,
    pub rotation_deg: f32,
    pub opacity: f32,
    pub font_size: f32,
    pub color_rgba: [u8; 4],
    pub background_rgba: Option<[u8; 4]>,
    pub bold: bool,
    pub italic: bool,
}

impl TextLayer {
    pub fn validate(&self) -> Result<(), TreeError> {
        if self.text.is_empty() || self.text.len() > 4096
            || self.scale <= 0.0 || !self.scale.is_finite()
            || !self.rotation_deg.is_finite()
            || self.font_size <= 0.0 || !self.font_size.is_finite()
            || !self.opacity.is_finite() || !(0.0..=1.0).contains(&self.opacity)
        {
            return Err(TreeError::Usage("invalid editor text layer".into()));
        }
        self.position.validate()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DrawStroke {
    pub points: Vec<Point>,
    pub brush: BrushSettings,
    pub color_rgba: [u8; 4],
    pub width: f32,
    pub opacity: f32,
}

impl DrawStroke {
    pub fn validate(&self) -> Result<(), TreeError> {
        self.brush.validate()?;
        if self.points.is_empty() || self.points.len() > 4096
            || self.width <= 0.0 || !self.width.is_finite()
            || !self.opacity.is_finite() || !(0.0..=1.0).contains(&self.opacity)
        {
            return Err(TreeError::Usage("invalid editor drawing stroke".into()));
        }
        for p in &self.points {
            p.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Filter {
    None,
    Mono,
    Sepia,
    Vivid,
    Cool,
    Warm,
    Fade,
    HighContrast,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MediaEditRecipe {
    pub source_width: u32,
    pub source_height: u32,
    pub crop: Option<CropRect>,
    pub rotation: Rotation,
    pub flip_horizontal: bool,
    pub flip_vertical: bool,
    pub adjustments: ImageAdjustments,
    pub filters: Vec<Filter>,
    pub text_layers: Vec<TextLayer>,
    pub strokes: Vec<DrawStroke>,
}

impl MediaEditRecipe {
    pub fn identity(width: u32, height: u32) -> Result<Self, TreeError> {
        if width == 0 || height == 0 {
            return Err(TreeError::Usage("editor source dimensions are invalid".into()));
        }
        Ok(Self {
            source_width: width,
            source_height: height,
            crop: None,
            rotation: Rotation::Deg0,
            flip_horizontal: false,
            flip_vertical: false,
            adjustments: ImageAdjustments::default(),
            filters: Vec::new(),
            text_layers: Vec::new(),
            strokes: Vec::new(),
        })
    }

    pub fn validate(&self) -> Result<(), TreeError> {
        if self.source_width == 0 || self.source_height == 0
            || self.filters.len() > MAX_FILTERS
            || self.text_layers.len() > MAX_TEXT_LAYERS
            || self.strokes.len() > MAX_DRAW_STROKES
        {
            return Err(TreeError::Usage("invalid media edit recipe".into()));
        }
        if let Some(crop) = self.crop {
            crop.validate()?;
            if crop.x + crop.width > self.source_width as f32
                || crop.y + crop.height > self.source_height as f32
            {
                return Err(TreeError::Usage("crop exceeds source dimensions".into()));
            }
        }
        self.adjustments.validate()?;
        for layer in &self.text_layers {
            layer.validate()?;
        }
        for stroke in &self.strokes {
            stroke.validate()?;
        }
        Ok(())
    }

    pub fn output_dimensions(&self) -> (u32, u32) {
        let (w, h) = self.crop.map(|c| (c.width.round() as u32, c.height.round() as u32))
            .unwrap_or((self.source_width, self.source_height));
        match self.rotation {
            Rotation::Deg90 | Rotation::Deg270 => (h, w),
            _ => (w, h),
        }
    }

    /// Canonical recipe bytes are used for cache identity and audit/debugging.
    /// They are not a cryptographic signature and must not be trusted as proof
    /// that a renderer actually applied an edit.
    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        self.validate()?;
        let json = serde_json::to_vec(self)
            .map_err(|e| TreeError::Usage(format!("editor recipe encode failed: {e}")))?;
        let mut out = Vec::with_capacity(8 + json.len());
        out.extend_from_slice(b"TREEEDIT");
        out.push(EDITOR_VERSION);
        out.extend_from_slice(&json);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_supports_rotation_crop_adjustments_text_and_drawing() {
        let mut recipe = MediaEditRecipe::identity(1920, 1080).unwrap();
        recipe.rotation = Rotation::Deg90;
        recipe.crop = Some(CropRect { x: 100.0, y: 50.0, width: 800.0, height: 600.0 });
        recipe.adjustments.exposure = 1.25;
        recipe.adjustments.saturation = 1.4;
        recipe.text_layers.push(TextLayer {
            text: "안전한 메시지".into(),
            position: Point { x: 0.5, y: 0.5 },
            scale: 1.0,
            rotation_deg: -8.0,
            opacity: 1.0,
            font_size: 48.0,
            color_rgba: [255, 255, 255, 255],
            background_rgba: None,
            bold: true,
            italic: false,
        });
        recipe.strokes.push(DrawStroke {
            brush: BrushSettings::default(),
            points: vec![Point { x: 0.1, y: 0.1 }, Point { x: 0.2, y: 0.2 }],
            color_rgba: [255, 0, 0, 255],
            width: 12.0,
            opacity: 0.8,
        });
        assert!(recipe.validate().is_ok());
        assert_eq!(recipe.output_dimensions(), (600, 800));
        assert!(!recipe.encode().unwrap().is_empty());
    }

    #[test]
    fn editor_rejects_nan_and_out_of_range_adjustments() {
        let mut recipe = MediaEditRecipe::identity(100, 100).unwrap();
        recipe.adjustments.exposure = f32::NAN;
        assert!(recipe.validate().is_err());
        recipe.adjustments.exposure = 0.0;
        recipe.adjustments.contrast = 4.0;
        assert!(recipe.validate().is_err());
    }
}
