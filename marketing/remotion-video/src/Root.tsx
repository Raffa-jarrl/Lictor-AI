import { Composition } from 'remotion';
import { LictorVideo } from './LictorVideo';

export const Root = () => {
  return (
    <Composition
      id="LictorTikTok"
      component={LictorVideo}
      durationInFrames={720}
      fps={30}
      width={1080}
      height={1920}
    />
  );
};
