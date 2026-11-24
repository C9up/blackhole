//! Bounds on the HTML the sanitizer parses.
//!
//! The HTML tree builder is not linear in its input. Misnested formatting
//! elements are re-created in every new block ("reconstruct the active
//! formatting elements"): `<font size=1><p><font size=2><p>…` builds n²/2
//! elements from n tags, and an allow-listed element carries that growth
//! into the sanitized output. Deep nesting is quadratic too: every start and
//! end tag scans the stack of open elements.
//!
//! The bounds are measured by html5ever itself, on the tree it builds, not
//! by a second reading of the markup: [`check`] runs the same parser the
//! sanitizer runs, with the same context element, into a sink that builds no
//! DOM — it records each element's parent and the size of what was built.
//! The input is fed a few bytes at a time and the parse stops at the first
//! feed that crossed a bound, so the refusal costs no more than the bound.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::rc::{Rc, Weak};

use html5ever::interface::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::{local_name, ns, parse_fragment, Attribute, ParseOpts, QualName};

/// Default for [`HtmlLimits::max_input_bytes`]: 1 MiB.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 1024 * 1024;

/// Default for [`HtmlLimits::max_depth`]: the nesting browsers stop at.
pub const DEFAULT_MAX_DEPTH: usize = 512;

/// The markup the parser builds may weigh this many times its input, on top
/// of [`EXPANSION_ALLOWANCE`]. Well-formed HTML weighs about its own size;
/// omitted end tags (`<li>`, `<td>`, `<p>`) about twice that.
pub const MAX_EXPANSION: usize = 4;

/// What any input may build whatever its size, so a short fragment with a
/// few misnested tags is never refused.
pub const EXPANSION_ALLOWANCE: usize = 64 * 1024;

/// How many bytes are parsed between two looks at the bounds. Small, so that
/// the work done past a bound before it is seen stays small too.
const FEED_BYTES: usize = 64;

/// The bounds the sanitizer holds an input to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtmlLimits {
    /// Longest input accepted, in UTF-8 bytes.
    pub max_input_bytes: usize,
    /// Deepest element accepted, the context element being depth 0.
    pub max_depth: usize,
}

impl Default for HtmlLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

/// Why an input was refused. [`HtmlRefusal::code`] is the stable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtmlRefusal {
    /// The input is longer than `max_input_bytes`.
    TooLarge { bytes: usize, max: usize },
    /// An element sits deeper than `max_depth`.
    TooDeep { max: usize },
    /// The tree built from the input weighs more than [`MAX_EXPANSION`] times
    /// the input plus [`EXPANSION_ALLOWANCE`].
    TooComplex { bytes: usize },
}

impl HtmlRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "E_BLACKHOLE_HTML_TOO_LARGE",
            Self::TooDeep { .. } => "E_BLACKHOLE_HTML_TOO_DEEP",
            Self::TooComplex { .. } => "E_BLACKHOLE_HTML_TOO_COMPLEX",
        }
    }
}

impl fmt::Display for HtmlRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, max } => write!(
                f,
                "the HTML to sanitize is {bytes} bytes, over xss.maxInputBytes ({max})"
            ),
            Self::TooDeep { max } => write!(
                f,
                "the HTML to sanitize nests elements deeper than xss.maxDepth ({max})"
            ),
            Self::TooComplex { bytes } => write!(
                f,
                "the HTML to sanitize builds more than {MAX_EXPANSION} times its {bytes} bytes of markup"
            ),
        }
    }
}

impl std::error::Error for HtmlRefusal {}

/// Refuse `input` when it crosses one of `limits` or builds too much markup.
pub fn check(input: &str, limits: &HtmlLimits) -> Result<(), HtmlRefusal> {
    if input.len() > limits.max_input_bytes {
        return Err(HtmlRefusal::TooLarge {
            bytes: input.len(),
            max: limits.max_input_bytes,
        });
    }
    let state = Rc::new(State {
        max_depth: limits.max_depth,
        budget: Cell::new(
            input
                .len()
                .saturating_mul(MAX_EXPANSION)
                .saturating_add(EXPANSION_ALLOWANCE),
        ),
        bytes: input.len(),
        refusal: Cell::new(None),
    });
    let sink = Measure {
        document: Node::new(None, false),
        state: Rc::clone(&state),
    };
    // The context ammonia parses a fragment in: a `<div>`, scripting off.
    let mut parser = parse_fragment(
        sink,
        ParseOpts::default(),
        QualName::new(None, ns!(html), local_name!("div")),
        Vec::new(),
        false,
    );
    let mut start = 0;
    while start < input.len() {
        let mut end = (start + FEED_BYTES).min(input.len());
        while !input.is_char_boundary(end) {
            end += 1;
        }
        parser.process(StrTendril::from_slice(&input[start..end]));
        if let Some(refusal) = state.refusal.get() {
            return Err(refusal);
        }
        start = end;
    }
    parser.finish();
    match state.refusal.get() {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
}

/// What the parse has used so far, shared by the sink and [`check`].
struct State {
    max_depth: usize,
    /// Bytes of markup the tree may still grow by.
    budget: Cell<usize>,
    bytes: usize,
    refusal: Cell<Option<HtmlRefusal>>,
}

impl State {
    fn spend(&self, weight: usize) {
        match self.budget.get().checked_sub(weight) {
            Some(left) => self.budget.set(left),
            None => self.refuse(HtmlRefusal::TooComplex { bytes: self.bytes }),
        }
    }

    fn refuse(&self, refusal: HtmlRefusal) {
        if self.refusal.get().is_none() {
            self.refusal.set(Some(refusal));
        }
    }
}

/// One node of the measured tree: its name, and where it hangs.
struct Node {
    /// `None` for the document, a fragment, a comment.
    name: Option<QualName>,
    mathml_annotation_xml_integration_point: bool,
    parent: RefCell<Weak<Node>>,
    children: RefCell<Vec<Rc<Node>>>,
    template_contents: RefCell<Option<Rc<Node>>>,
}

impl Node {
    fn new(name: Option<QualName>, integration_point: bool) -> Rc<Self> {
        Rc::new(Self {
            name,
            mathml_annotation_xml_integration_point: integration_point,
            parent: RefCell::new(Weak::new()),
            children: RefCell::new(Vec::new()),
            template_contents: RefCell::new(None),
        })
    }

    fn parent(&self) -> Option<Rc<Node>> {
        self.parent.borrow().upgrade()
    }
}

impl Drop for Node {
    // Iterative: a deep tree dropped one level per call would overflow the
    // stack long before it reached a bound worth refusing.
    fn drop(&mut self) {
        let mut nodes = std::mem::take(&mut *self.children.borrow_mut());
        nodes.extend(self.template_contents.borrow_mut().take());
        while let Some(node) = nodes.pop() {
            nodes.extend(std::mem::take(&mut *node.children.borrow_mut()));
            nodes.extend(node.template_contents.borrow_mut().take());
        }
    }
}

/// The depth of `node` from its parents, counted up to `cap` at most: a node
/// is measured where it hangs now, whatever moved it since it was created.
fn depth_of(node: &Rc<Node>, cap: usize) -> usize {
    let mut depth = 0;
    let mut current = node.parent();
    while let Some(parent) = current {
        depth += 1;
        if depth > cap {
            break;
        }
        current = parent.parent();
    }
    depth
}

fn detach(node: &Rc<Node>) {
    if let Some(parent) = node.parent() {
        parent
            .children
            .borrow_mut()
            .retain(|child| !Rc::ptr_eq(child, node));
    }
    *node.parent.borrow_mut() = Weak::new();
}

/// A [`TreeSink`] that keeps the shape of the tree and its weight, nothing
/// else. It answers the tree builder's questions (names, identity, template
/// contents) the way a DOM does, so the parse it drives is the one the
/// sanitizer runs.
struct Measure {
    document: Rc<Node>,
    state: Rc<State>,
}

impl Measure {
    /// Hang `child` under `parent`, at `index` or last, and measure it.
    fn attach(&self, parent: &Rc<Node>, child: NodeOrText<Rc<Node>>, index: Option<usize>) {
        match child {
            NodeOrText::AppendText(text) => self.state.spend(text.len()),
            NodeOrText::AppendNode(node) => {
                detach(&node);
                *node.parent.borrow_mut() = Rc::downgrade(parent);
                {
                    let mut children = parent.children.borrow_mut();
                    match index {
                        Some(at) => children.insert(at, Rc::clone(&node)),
                        None => children.push(Rc::clone(&node)),
                    }
                }
                self.measure_depth(&node);
            }
        }
    }

    fn measure_depth(&self, node: &Rc<Node>) {
        // The fragment's root `<html>` hangs under the document: the context
        // element's children are at depth 2 from the document.
        let max = self.state.max_depth + 1;
        if depth_of(node, max) > max {
            self.state.refuse(HtmlRefusal::TooDeep {
                max: self.state.max_depth,
            });
        }
    }
}

/// What an element adds to the serialized markup: `<name attrs></name>`.
fn element_weight(name: &QualName, attrs: &[Attribute]) -> usize {
    attrs.iter().fold(name.local.len() * 2 + 5, |weight, attr| {
        weight + attr.name.local.len() + attr.value.len() + 4
    })
}

impl TreeSink for Measure {
    type Handle = Rc<Node>;
    type Output = ();
    type ElemName<'a> = &'a QualName;

    fn finish(self) {}

    fn parse_error(&self, _msg: std::borrow::Cow<'static, str>) {}

    fn get_document(&self) -> Rc<Node> {
        Rc::clone(&self.document)
    }

    fn elem_name<'a>(&'a self, target: &'a Rc<Node>) -> &'a QualName {
        match target.name {
            Some(ref name) => name,
            None => unreachable!("the tree builder asked the name of a node that is no element"),
        }
    }

    fn create_element(
        &self,
        name: QualName,
        attrs: Vec<Attribute>,
        flags: ElementFlags,
    ) -> Rc<Node> {
        self.state.spend(element_weight(&name, &attrs));
        let node = Node::new(Some(name), flags.mathml_annotation_xml_integration_point);
        if flags.template {
            // The contents serialize inside the template: they hang under it.
            let contents = Node::new(None, false);
            *contents.parent.borrow_mut() = Rc::downgrade(&node);
            *node.template_contents.borrow_mut() = Some(contents);
        }
        node
    }

    fn create_comment(&self, text: StrTendril) -> Rc<Node> {
        self.state.spend(text.len() + 7);
        Node::new(None, false)
    }

    fn create_pi(&self, target: StrTendril, data: StrTendril) -> Rc<Node> {
        self.state.spend(target.len() + data.len() + 4);
        Node::new(None, false)
    }

    fn append(&self, parent: &Rc<Node>, child: NodeOrText<Rc<Node>>) {
        self.attach(parent, child, None);
    }

    fn append_based_on_parent_node(
        &self,
        element: &Rc<Node>,
        prev_element: &Rc<Node>,
        child: NodeOrText<Rc<Node>>,
    ) {
        if element.parent().is_some() {
            self.append_before_sibling(element, child);
        } else {
            self.append(prev_element, child);
        }
    }

    fn append_doctype_to_document(
        &self,
        name: StrTendril,
        _public: StrTendril,
        _system: StrTendril,
    ) {
        self.state.spend(name.len() + 11);
    }

    fn get_template_contents(&self, target: &Rc<Node>) -> Rc<Node> {
        match target.template_contents.borrow().as_ref() {
            Some(contents) => Rc::clone(contents),
            None => unreachable!(
                "the tree builder asked the contents of an element that is no template"
            ),
        }
    }

    fn same_node(&self, x: &Rc<Node>, y: &Rc<Node>) -> bool {
        Rc::ptr_eq(x, y)
    }

    fn set_quirks_mode(&self, _mode: QuirksMode) {}

    fn append_before_sibling(&self, sibling: &Rc<Node>, new_node: NodeOrText<Rc<Node>>) {
        let Some(parent) = sibling.parent() else {
            unreachable!("the tree builder inserted before a node that has no parent")
        };
        if let NodeOrText::AppendNode(ref node) = new_node {
            detach(node);
        }
        let index = parent
            .children
            .borrow()
            .iter()
            .position(|child| Rc::ptr_eq(child, sibling));
        self.attach(&parent, new_node, index);
    }

    fn add_attrs_if_missing(&self, _target: &Rc<Node>, attrs: Vec<Attribute>) {
        let weight = attrs.iter().fold(0, |weight, attr| {
            weight + attr.name.local.len() + attr.value.len() + 4
        });
        self.state.spend(weight);
    }

    fn remove_from_parent(&self, target: &Rc<Node>) {
        detach(target);
    }

    fn reparent_children(&self, node: &Rc<Node>, new_parent: &Rc<Node>) {
        let moved = std::mem::take(&mut *node.children.borrow_mut());
        for child in &moved {
            *child.parent.borrow_mut() = Rc::downgrade(new_parent);
        }
        new_parent.children.borrow_mut().extend(moved);
        // The children now hang one level under `new_parent`: measuring one
        // of them measures them all.
        if let Some(child) = new_parent.children.borrow().last() {
            self.measure_depth(child);
        }
    }

    fn is_mathml_annotation_xml_integration_point(&self, handle: &Rc<Node>) -> bool {
        handle.mathml_annotation_xml_integration_point
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_depth: usize) -> HtmlLimits {
        HtmlLimits {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_depth,
        }
    }

    #[test]
    fn an_ordinary_fragment_passes() {
        let input = "<div class=\"card\"><h1>T</h1><p>a <b>b</b> <i>c</i></p><ul><li>1<li>2</ul>\
                     <table><tr><td>x<td>y</table><template><p>t</p></template></div>";
        assert_eq!(check(input, &HtmlLimits::default()), Ok(()));
        // Text is weighed by its length, not by how the tokenizer hands it
        // over (each character reference on its own).
        assert_eq!(
            check(&"&nbsp;".repeat(5_000), &HtmlLimits::default()),
            Ok(())
        );
        let paragraphs = format!("<p>{}</p>", "&nbsp;".repeat(20)).repeat(500);
        assert_eq!(check(&paragraphs, &HtmlLimits::default()), Ok(()));
        // Omitted end tags weigh about twice the input.
        assert_eq!(
            check(&"<li>x".repeat(20_000), &HtmlLimits::default()),
            Ok(())
        );
    }

    #[test]
    fn the_input_length_is_bounded_before_parsing() {
        let tight = HtmlLimits {
            max_input_bytes: 10,
            max_depth: DEFAULT_MAX_DEPTH,
        };
        assert_eq!(check("0123456789", &tight), Ok(()));
        assert_eq!(
            check("0123456789a", &tight),
            Err(HtmlRefusal::TooLarge { bytes: 11, max: 10 })
        );
    }

    #[test]
    fn depth_is_counted_from_the_context_element() {
        // The context `<div>` is depth 0; each nested `<div>` one more.
        assert_eq!(check(&"<div>".repeat(5), &limits(5)), Ok(()));
        assert_eq!(
            check(&"<div>".repeat(6), &limits(5)),
            Err(HtmlRefusal::TooDeep { max: 5 })
        );
    }

    #[test]
    fn depth_is_measured_on_the_tree_the_parser_builds() {
        // Shapes a reading of the markup gets wrong, each the parser nests.
        let shapes = [
            "<!--><div>".repeat(40),
            "<!---><div>".repeat(40),
            "<textarea><!--</textarea><div>".repeat(40),
            "<title><!--</title><div>".repeat(40),
            "<style><!--</style><div>".repeat(40),
            // Implied ancestors: one tag, several levels.
            "<table><tr><td>".repeat(20),
            // Formatting elements re-created in every new paragraph.
            (0..40).map(|i| format!("<font size={i}><p>")).collect(),
            // A formatting element closed over open blocks: the adoption
            // agency moves them, and they stay open.
            format!("<b>{}</b>", "<div>".repeat(10)).repeat(4),
            format!("<b><i>{}</b>", "<div>".repeat(10)).repeat(4),
        ];
        for shape in shapes {
            assert_eq!(
                check(&shape, &limits(30)),
                Err(HtmlRefusal::TooDeep { max: 30 }),
                "not refused: {}",
                &shape[..60.min(shape.len())]
            );
        }
    }

    #[test]
    fn misnested_formatting_is_refused_once_it_outgrows_its_input() {
        // Each `<p>x` closes the paragraph the `<b>`s were open in, and the
        // text re-creates all of them in the new one: 4 bytes of input, 400
        // elements of output, at a depth the default bound accepts.
        let mut input = String::from("<p>");
        input.extend((0..400).map(|i| format!("<b title={i}>")));
        input.push_str(&"<p>x".repeat(400));
        assert_eq!(
            check(&input, &HtmlLimits::default()),
            Err(HtmlRefusal::TooComplex { bytes: input.len() })
        );
        // A few re-creations are well within the allowance.
        assert_eq!(check("<p><b>x<p>y<p>z</b>", &HtmlLimits::default()), Ok(()));
    }

    #[test]
    fn the_refusal_costs_no_more_than_the_bound() {
        // Quadratic shapes at 1x and 4x: once refused, the larger input does
        // not cost 16 times the smaller (linear would be 4; allow noise).
        let shape =
            |n: usize| -> String { (0..n).map(|i| format!("<font size={i}><p>")).collect() };
        let time = |input: &str| {
            let started = std::time::Instant::now();
            for _ in 0..5 {
                assert!(check(input, &HtmlLimits::default()).is_err());
            }
            started.elapsed()
        };
        let small = shape(1_000);
        let large = shape(4_000);
        time(&small);
        let (small_time, large_time) = (time(&small), time(&large));
        assert!(
            large_time < small_time * 8,
            "{small_time:?} for {} bytes, {large_time:?} for {} bytes",
            small.len(),
            large.len()
        );
    }

    #[test]
    fn the_codes_are_stable() {
        assert_eq!(
            HtmlRefusal::TooLarge { bytes: 2, max: 1 }.code(),
            "E_BLACKHOLE_HTML_TOO_LARGE"
        );
        assert_eq!(
            HtmlRefusal::TooDeep { max: 1 }.code(),
            "E_BLACKHOLE_HTML_TOO_DEEP"
        );
        assert_eq!(
            HtmlRefusal::TooComplex { bytes: 1 }.code(),
            "E_BLACKHOLE_HTML_TOO_COMPLEX"
        );
    }
}
