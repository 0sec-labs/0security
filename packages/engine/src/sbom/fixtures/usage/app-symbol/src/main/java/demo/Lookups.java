package demo;
import org.apache.logging.log4j.LogManager;

class Lookups {
  // org.apache.logging.log4j.core.lookup.NotACall is mentioned in a comment only
  Object make() { return new org.apache.logging.log4j.core.lookup.JndiLookup(); }
}
