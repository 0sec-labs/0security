//! Kotlin extractor (placeholder while the Java work compiles).

use super::FileGraph;
use tree_sitter::Node;

pub(super) fn extract(_rel: &str, _source: &str, _root: Node) -> FileGraph {
    FileGraph::default()
}
