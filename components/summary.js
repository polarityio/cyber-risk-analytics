"use strict";
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias("block.data.details"),
  emails: Ember.computed("details.email", function () {
    return Object.keys(this.details.email).reduce(
      (agg, key) => agg.concat(Object.assign({}, this.details.email[key])),
      []
    );
  }),
});
