<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

get_header();
?>
<main id="jupiterx-main" class="jupiterx-main">
	<div class="jupiterx-main-content">
		<div class="container">
			<div class="row">
				<div id="jupiterx-primary" class="jupiterx-primary col-lg-12">
					<div class="jupiterx-content" role="main" itemprop="mainEntityOfPage">
						<article <?php post_class( 'jupiterx-post' ); ?> itemscope="itemscope" itemtype="http://schema.org/CreativeWork">
							<div class="jupiterx-post-body" itemprop="articleBody">
								<div class="jupiterx-post-content clearfix" itemprop="text">
									<?php echo Abiquifi_Public_SSO::instance()->render_current_public_page_content(); ?>
								</div>
							</div>
						</article>
					</div>
				</div>
			</div>
		</div>
	</div>
</main>
<?php
get_footer();
