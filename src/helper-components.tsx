import { Subtitle1, Divider } from "@fluentui/react-components";
import { FlexProps } from "./interfaces";

const Row: React.FC<FlexProps> = ({ children, css_ = {} }) => (
  <div css={{ display: "flex", flexDirection: "row", ...css_ }}>{children}</div>
);

const Col: React.FC<FlexProps> = ({ children, css_ }) => (
  <div css={{ display: "flex", flexDirection: "column", ...css_ }}>
    {children}
  </div>
);

const SectionTitle: React.FC<{ label: string }> = ({ label }) => (
  <Row css_={{ gap: "16px", width: "100%" }}>
    <Subtitle1 css={{ flexShrink: 0 }}>{label}</Subtitle1>
    <Divider appearance="strong" />
  </Row>
);

export { Row, Col, SectionTitle };
