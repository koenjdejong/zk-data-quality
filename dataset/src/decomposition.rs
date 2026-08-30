#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enabled {

    pub commitment: bool,

    pub fingerprint: bool,

    pub p1: bool,

    pub p2: bool,

    pub p3: bool,

    pub p4: bool,

    pub order1: bool,

    pub product1: bool,

    pub p5: bool,

    pub order2: bool,

    pub product2: bool,

    pub p6: bool,
}

impl Default for Enabled {
    fn default() -> Self {
        Self::all()
    }
}

impl Enabled {
    pub const NAMES: [&'static str; 12] = [
        "commitment",
        "fingerprint",
        "p1",
        "p2",
        "p3",
        "p4",
        "order1",
        "product1",
        "p5",
        "order2",
        "product2",
        "p6",
    ];

    pub fn all() -> Self {
        Self {
            commitment: true,
            fingerprint: true,
            p1: true,
            p2: true,
            p3: true,
            p4: true,
            order1: true,
            product1: true,
            p5: true,
            order2: true,
            product2: true,
            p6: true,
        }
    }

    pub fn none() -> Self {
        Self {
            commitment: false,
            fingerprint: false,
            p1: false,
            p2: false,
            p3: false,
            p4: false,
            order1: false,
            product1: false,
            p5: false,
            order2: false,
            product2: false,
            p6: false,
        }
    }

    pub fn sigma1(&self) -> bool {
        self.order1 || self.product1
    }

    pub fn sigma2(&self) -> bool {
        self.order2 || self.product2
    }

    pub fn any_grand_product(&self) -> bool {
        self.product1 || self.product2
    }

    pub fn needs_record_fingerprint(&self) -> bool {
        self.fingerprint || self.any_grand_product()
    }

    fn switch(&mut self, name: &str) -> Result<(), String> {
        match name {
            "commitment" => self.commitment = true,
            "fingerprint" => self.fingerprint = true,
            "p1" => self.p1 = true,
            "p2" => self.p2 = true,
            "p3" => self.p3 = true,
            "p4" => self.p4 = true,
            "order1" => self.order1 = true,
            "product1" => self.product1 = true,
            "p5" => self.p5 = true,
            "order2" => self.order2 = true,
            "product2" => self.product2 = true,
            "p6" => self.p6 = true,
            other => {
                return Err(format!(
                    "unknown switch {other:?}; known are {}",
                    Self::NAMES.join(", ")
                ))
            }
        }
        Ok(())
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed == "none" {
            return Ok(Self::none());
        }
        let mut enabled = Self::none();
        for name in trimmed.split(',').map(str::trim).filter(|part| !part.is_empty()) {
            enabled.switch(name)?;
        }
        enabled.validate()?;
        Ok(enabled)
    }

    pub fn from_arguments<'a>(
        arguments: impl IntoIterator<Item = &'a String>,
    ) -> Result<Self, String> {
        let mut enabled = Self::all();
        for argument in arguments {
            if let Some(value) = argument.strip_prefix("--enable=") {
                enabled = Self::parse(value)?;
            }
        }
        Ok(enabled)
    }

    pub fn validate(&self) -> Result<(), String> {
        for (switch, name, required, required_name) in [
            (self.p5, "p5", self.order1, "order1"),
            (self.p6, "p6", self.order2, "order2"),
        ] {
            if switch && !required {
                return Err(format!(
                    "{name} is an adjacency check on a claimed ordering, so it needs \
                     {required_name}; without it the check is the unsoundness the audit was built \
                     around"
                ));
            }
        }
        Ok(())
    }

    pub fn to_list(&self) -> String {
        let present = [
            self.commitment,
            self.fingerprint,
            self.p1,
            self.p2,
            self.p3,
            self.p4,
            self.order1,
            self.product1,
            self.p5,
            self.order2,
            self.product2,
            self.p6,
        ];
        let names: Vec<&str> = Self::NAMES
            .iter()
            .zip(present)
            .filter(|(_, on)| *on)
            .map(|(name, _)| *name)
            .collect();
        names.join(",")
    }
}
