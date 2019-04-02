module se.uu.ub.cora.gatekeeperclient {
	requires transitive se.uu.ub.cora.spider;
	requires transitive se.uu.ub.cora.httphandler;

	exports se.uu.ub.cora.gatekeeperclient.authentication;
}