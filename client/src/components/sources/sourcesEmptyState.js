import React, { Component } from 'react';
import { connect } from 'react-redux';
import { withRouter } from 'react-router';

import { Button, EmptyState, Grid, Row } from 'patternfly-react';

class SourcesEmptyState extends Component {
  render() {
    return (
      <Grid fluid>
        <Row>
          <EmptyState className="full-page-blank-slate">
            <EmptyState.Icon />
            <EmptyState.Title>
              Welcome to Red Hat Entitlements Reporting
            </EmptyState.Title>
            <EmptyState.Info>
              Add some networks to search for Red Hat products. You can add them
              here or download a spreadsheet template.
            </EmptyState.Info>
            <EmptyState.Action>
              <Button bsStyle="primary" bsSize="large">
                Add Source
              </Button>
            </EmptyState.Action>
            <EmptyState.Action secondary>
              <Button bsStyle="default" bsSize="large">
                Import Sources
              </Button>
            </EmptyState.Action>
          </EmptyState>
        </Row>
      </Grid>
    );
  }
}

SourcesEmptyState.propTypes = {};

function mapStateToProps(state, ownProps) {
  return state;
}

export default withRouter(connect(mapStateToProps)(SourcesEmptyState));